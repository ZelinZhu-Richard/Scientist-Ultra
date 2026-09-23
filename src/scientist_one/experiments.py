"""Provider-neutral experiment and compute-backend contracts.

Successful process exit is not scientific evidence.  A run is collectable only
after its frozen run specification, all planned seeds, evaluator binding,
output hashes, and required ablations validate.  The local backend executes a
single explicit argv vector with a scrubbed environment, no shell, no network
executable, bounded logs, and no automatic retry or backend fallback.

The fake GPU backend is a deterministic scheduler fixture.  It is always
``UNTESTED``, records ``network_used=false``, and can never produce scientific
evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields as dataclass_fields
from datetime import datetime
from enum import StrEnum
import errno
import hashlib
import math
import os
from pathlib import Path, PurePath
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Callable, Iterable, Mapping, Protocol, runtime_checkable

from .artifacts import (
    MAX_ARTIFACT_PARENTS,
    MAX_REGISTRY_RECORDS,
    ArtifactRecord,
    ArtifactRegistry,
    RegistryValidationResult,
)
from .errors import ArtifactError, IntegrityError, PathSecurityError, ValidationError
from .bounded_mean_inference import (
    BOUNDED_MEAN_DECISION_RULE_ID,
    BOUNDED_MEAN_INTERVAL_METHOD_ID,
    BOUNDED_MEAN_PROFILE_ID,
    BOUNDED_MEAN_ZERO_P_METHOD_ID,
    BoundedMeanInferencePlan,
)
from .ledger import (
    MAX_LEDGER_BYTES,
    MAX_LEDGER_EVENTS,
    EventLedger,
    LedgerEvent,
    LedgerValidationResult,
)
from .local_terminal_observation import (
    LOCAL_TERMINAL_CAPTURE_METADATA_KEY,
    LOCAL_TERMINAL_CAPTURE_PROFILE,
    LOCAL_TERMINAL_MAX_FILE_BYTES,
    LOCAL_TERMINAL_MAX_JSON_BYTES,
    LOCAL_TERMINAL_MAX_LOG_BYTES,
    LOCAL_TERMINAL_MAX_OUTPUTS,
    LOCAL_TERMINAL_MAX_SOURCE_BYTES,
    LOCAL_TERMINAL_MAX_TOTAL_BYTES,
    LOCAL_TERMINAL_OBSERVATION_FILENAME,
    LocalTerminalFile,
    LocalTerminalObservation,
    validate_terminal_capture_limits,
)
from .models import (
    MacroState,
    freeze_json,
    thaw_json,
    validate_identifier,
    validate_sha256,
)
from .roles import Role
from .security import (
    atomic_write_bytes,
    atomic_write_json,
    canonical_json_bytes,
    canonical_root,
    open_confined_directory_fd,
    read_confined_bytes,
    resolve_confined,
    safe_json_loads,
    secure_directory,
    validate_command,
)

if TYPE_CHECKING:
    from .dataset_statistical_use import DatasetStatisticalUseAuthority
    from .generic_ml_projection import GenericMLReferenceWork, GenericMLReferenceWorkPolicy
    from .research_state import ScientificDatasetAuthority, ScientificDatasetSplitAuthority


MAX_RUN_SEEDS = 10_000
MAX_OUTPUT_ARTIFACTS = 10_000
MAX_ABLATIONS = 1_000
MAX_OUTPUT_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_RETURNED_ARTIFACT_TOTAL_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_LOG_BYTES = 4 * 1024 * 1024
PREEMPTED_EXIT_CODE = 75
MAX_COMPUTE_MEMORY_BYTES = 16 * 1024**5
MAX_COMPUTE_STORAGE_BYTES = 128 * 1024**5
MAX_COMPUTE_CONCURRENCY = 256
MAX_BATCH_SIZE = 1_000_000
LOCAL_PROCESS_TERM_GRACE_SECONDS = 0.5
LOCAL_PROCESS_KILL_GRACE_SECONDS = 2.0
LOCAL_MAC_SANDBOX_EXECUTABLE = "/usr/bin/sandbox-exec"
LOCAL_MAC_ISOLATION_SCHEMA = "SCIENTIST_ONE_LOCAL_MAC_ISOLATION_LAUNCH_V1"
LOCAL_MAC_SANDBOX_PROFILE_SCHEMA = "SCIENTIST_ONE_LOCAL_MAC_SEATBELT_PROFILE_V1"
LOCAL_MAC_MAX_ISOLATED_LAUNCHES = 1_024
LOCAL_MAC_EXECUTION_INPUT_BINDING_SCHEMA = (
    "SCIENTIST_ONE_LOCAL_MAC_EXECUTION_INPUT_BINDING_V1"
)
LOCAL_MAC_EXECUTION_INPUT_KINDS = (
    "code",
    "data",
    "configuration",
    "evaluator",
)
LOCAL_MAC_EXECUTION_MODE_SCHEMA = "SCIENTIST_ONE_LOCAL_MAC_EXECUTION_MODE_V1"
COMPUTE_ESCALATION_INPUT_SCHEMA = "SCIENTIST_ONE_COMPUTE_ESCALATION_INPUT_V1"
COMPUTE_ESCALATION_PLAN_AUTHORITY_V1_SCHEMA = (
    "SCIENTIST_ONE_COMPUTE_ESCALATION_PLAN_AUTHORITY_V1"
)
COMPUTE_ESCALATION_PLAN_AUTHORITY_SCHEMA = (
    "SCIENTIST_ONE_COMPUTE_ESCALATION_PLAN_AUTHORITY_V2"
)
COMPUTE_ESCALATION_PLAN_AUTHORITY_LOGICAL_TYPE = (
    "compute_escalation_plan_authority"
)
COMPUTE_ESCALATION_EVENT_SCHEMA = "SCIENTIST_ONE_COMPUTE_ESCALATION_EVENT_V2"
COMPUTE_ESCALATION_LOCAL_SPEC_LOGICAL_TYPE = "compute_escalation_local_run_spec"
COMPUTE_ESCALATION_CLOUD_SPEC_LOGICAL_TYPE = "compute_escalation_cloud_run_spec"
COMPUTE_ESCALATION_SOURCE_PROFILE_LOGICAL_TYPE = (
    "compute_escalation_source_profile"
)
COMPUTE_ESCALATION_TARGET_PROFILE_LOGICAL_TYPE = (
    "compute_escalation_target_profile"
)
COMPUTE_ESCALATION_TARGET_ESTIMATE_LOGICAL_TYPE = (
    "compute_escalation_target_estimate"
)
COMPUTE_ESCALATION_BUDGET_LOGICAL_TYPE = "compute_escalation_budget"
COMPUTE_ESCALATION_DECISION_LOGICAL_TYPE = "compute_escalation_decision"
COMPUTE_ESCALATION_PLAN_LOGICAL_TYPE = "compute_escalation_submission_plan"
COMPUTE_ESCALATION_HUMAN_GATE_POLICY_LOGICAL_TYPE = (
    "compute_escalation_human_gate_policy"
)
COMPUTE_ESCALATION_SUBMISSION_CONSUMPTION_SCHEMA = (
    "SCIENTIST_ONE_COMPUTE_ESCALATION_SUBMISSION_CONSUMPTION_V2"
)
COMPUTE_ESCALATION_SUBMISSION_AUTHORIZATION_SCHEMA = (
    "SCIENTIST_ONE_COMPUTE_ESCALATION_SUBMISSION_AUTHORIZATION_V2"
)
COMPUTE_ESCALATION_SUBMISSION_AUTHORIZATION_LOGICAL_TYPE = (
    "compute_escalation_submission_authorization"
)
_COMPUTE_ESCALATION_INPUT_ORIGIN = "source-owned compute-escalation plan input"
_COMPUTE_ESCALATION_COMMAND = (
    "scientist-one",
    "verify-compute-escalation-plan",
)
_COMPUTE_ESCALATION_SUBMISSION_AUTHORIZATION_ORIGIN = (
    "source-owned scheduled GPU gate-policy evaluation"
)
_COMPUTE_ESCALATION_SUBMISSION_AUTHORIZATION_COMMAND = (
    "scientist-one",
    "authorize-scheduled-gpu-submission",
)

SCIENTIFIC_EXECUTION_PLAN_SCHEMA = "scientific-execution-plan/v1"
SCIENTIFIC_EXECUTION_PLAN_LOGICAL_TYPE = "scientific_execution_plan"
SCIENTIFIC_EXECUTION_INPUT_BINDING_SCHEMA = (
    "scientific-execution-input-binding/v1"
)
SCIENTIFIC_EXECUTION_INPUT_BINDING_LOGICAL_TYPE = (
    "scientific_execution_input_binding"
)
SCIENTIFIC_EXECUTION_PREPARATION_SCHEMA = (
    "scientific-execution-preparation/v1"
)
SCIENTIFIC_EXECUTION_PREPARATION_LOGICAL_TYPE = (
    "scientific_execution_preparation"
)
SCIENTIFIC_EXECUTION_PREPARATION_EVENT_SCHEMA = (
    "scientific-execution-prepared-event/v1"
)
SCIENTIFIC_EXECUTION_AUTHORITY_SCHEMA = "scientific_execution_authority/v1"
SCIENTIFIC_EXECUTION_AUTHORITY_SCHEMA_V2 = (
    "SCIENTIST_ONE_SCIENTIFIC_EXECUTION_AUTHORITY_V2"
)
SCIENTIFIC_EXECUTION_AUTHORITY_LOGICAL_TYPE = "scientific_execution_authority"
SCIENTIFIC_EXECUTION_AUTHORITY_EVENT_SCHEMA = (
    "scientific-execution-attested-event/v1"
)
SCIENTIFIC_EXECUTION_AUTHORITY_EVENT_SCHEMA_V2 = (
    "scientific-execution-attested-event/v2"
)
SCIENTIFIC_EXECUTION_AUTHORITY_PUBLICATION_EVENT_SCHEMA = (
    "scientific-execution-authority-publication/v1"
)
SCIENTIFIC_EXECUTION_ENVIRONMENT_LOGICAL_TYPE = (
    "scientific_execution_environment"
)
SCIENTIFIC_EXECUTION_ENVIRONMENT_SCHEMA = (
    "scientific-execution-environment/v1"
)
SCIENTIFIC_EXECUTION_ISOLATION_LOGICAL_TYPE = (
    "scientific_execution_isolation_attestation"
)
SCIENTIFIC_EXECUTION_ISOLATION_SCHEMA = (
    "scientific-execution-isolation-attestation/v1"
)
SCIENTIFIC_BACKEND_ATTESTATION_LOGICAL_TYPE = "backend_execution_attestation"
SCIENTIFIC_BACKEND_ATTESTATION_ENVELOPE_SCHEMA = (
    "backend-execution-attestation-envelope/v1"
)
SCIENTIFIC_BACKEND_ATTESTATION_ENVELOPE_SCHEMA_V2 = (
    "backend-execution-attestation-envelope/v2"
)
SCIENTIFIC_BACKEND_EXECUTION_CLAIM_SCHEMA = (
    "scientific-backend-execution-claim/v1"
)
SCIENTIFIC_BACKEND_EXECUTION_CLAIM_SCHEMA_V2 = (
    "SCIENTIST_ONE_SCIENTIFIC_BACKEND_EXECUTION_CLAIM_V2"
)
SCIENTIFIC_EXECUTION_ACTIVITY_SCHEMA = "SCIENTIST_ONE_EXECUTION_ACTIVITY_V1"
SCIENTIFIC_EXECUTION_ACTIVITY_LOGICAL_TYPE = "scientific_execution_activity"
COMPLETE_GENERIC_ML_ACTIVITY_PROFILE = "COMPLETE_GENERIC_ML_ACTIVITY_V1"
SCIENTIFIC_COMPLETE_ACTIVITY_ATTESTATION_SCHEMA = (
    "SCIENTIST_ONE_COMPLETE_GENERIC_ML_ACTIVITY_ATTESTATION_V1"
)
SCIENTIFIC_EXECUTION_SYSTEM_FIXTURE_LOGICAL_TYPE = (
    "scientific_execution_system_fixture"
)
SCIENTIFIC_METHOD_DEFINITION_BINDING_SCHEMA = (
    "SCIENTIST_ONE_SOURCE_OWNED_METHOD_DEFINITION_BINDING_V1"
)
SCIENTIFIC_METHOD_DEFINITION_BINDING_PROFILE = (
    "SOURCE_OWNED_METHOD_DEFINITION_V1"
)
SCIENTIFIC_METHOD_DEFINITION_BINDING_METADATA_KEY = (
    "scientific_method_definition_binding"
)
SCIENTIFIC_STATISTICAL_USE_BINDING_SCHEMA = (
    "SCIENTIST_ONE_STATISTICAL_USE_BINDING_V1"
)
SCIENTIFIC_STATISTICAL_USE_BINDING_METADATA_KEY = "scientific_statistical_use_binding"
SCIENTIFIC_REFERENCE_WORK_POLICY_METADATA_KEY = "scientific_reference_work_policy"
_MAX_SCIENTIFIC_EXECUTION_LEDGER_EVENT_BYTES = 256 * 1024

_SCIENTIFIC_EXECUTION_PREPARATION_ORIGIN = (
    "source-owned prospective scientific execution preparation"
)
_SCIENTIFIC_EXECUTION_PREPARATION_COMMAND = (
    "scientist-one",
    "prepare-scientific-execution",
)
_SCIENTIFIC_EXECUTION_AUTHORITY_ORIGIN = (
    "source-owned independently attested scientific execution"
)
_SCIENTIFIC_EXECUTION_AUTHORITY_COMMAND = (
    "scientist-one",
    "verify-scientific-execution",
)
_SCIENTIFIC_EXECUTION_ACTIVITY_ORIGIN = (
    "backend-captured exhaustive scientific execution activity"
)
_SCIENTIFIC_EXECUTION_ACTIVITY_COMMAND = (
    "scientist-one",
    "capture-scientific-execution-activity",
)


class ExperimentError(ValidationError):
    """An experiment specification or operation violates its contract."""


class ExperimentIntegrityError(IntegrityError):
    """Experiment output no longer matches its frozen bindings."""


class SubmissionConflictError(ExperimentError):
    """An idempotency or scientific-run identity was reused inconsistently."""


class ConfirmatoryPolicyError(ExperimentError):
    """A confirmatory retry or backend fallback was attempted."""


class ScientificExecutionAuthorityUnavailable(ExperimentError):
    """No production source owner can verify the backend attestation."""


@dataclass(frozen=True, slots=True)
class ScientificReferenceWorkBinding:
    """Ephemeral, freshly replayed prospective sources; not issued authority.

    The policy grants no observed resource equivalence. Consumers must call
    the full resolver, never accept a caller-constructed companion as proof.
    The four input records retain the execution owner's exact order.
    """

    policy: GenericMLReferenceWorkPolicy
    run_id: str
    execution_run_id: str
    frozen_run_spec_sha256: str
    contract_record: ArtifactRecord
    statistical_use_authority: DatasetStatisticalUseAuthority
    statistical_use_record: ArtifactRecord
    dataset_authority: ScientificDatasetAuthority
    dataset_record: ArtifactRecord
    dataset_acquisition_plan_record: ArtifactRecord
    raw_data_record: ArtifactRecord
    confirmatory_split_authority: ScientificDatasetSplitAuthority
    confirmatory_split_record: ArtifactRecord
    input_records: tuple[ArtifactRecord, ...]
    reference_work: GenericMLReferenceWork
    timeout_seconds: float
    contract_wall_cap_seconds: float

    @property
    def source_records(self) -> tuple[ArtifactRecord, ...]:
        return (
            self.contract_record,
            self.statistical_use_record,
            self.dataset_record,
            self.dataset_acquisition_plan_record,
            self.raw_data_record,
            self.confirmatory_split_record,
            *self.input_records,
        )


def _require_scientific_reference_work_source_chronology(
    records: tuple[ArtifactRecord, ...],
    *,
    timestamp: str,
) -> None:
    """Pure creation-order check; supplied records confer no source authority."""

    if type(records) is not tuple or not records or any(type(record) is not ArtifactRecord for record in records):
        raise ExperimentError("reference-work chronology requires exact source records")
    later = _scientific_execution_timestamp(timestamp, "reference-work consumption time")
    if any(
        _scientific_execution_timestamp(record.created_at, "reference-work source creation time") > later
        for record in records
    ):
        raise ExperimentError("reference-work source creation follows its spec or design freeze")


def _require_reference_work_statistical_use_before_spec(
    record: ArtifactRecord,
    *,
    timestamp: str,
) -> None:
    """Mirror the statistical owner's strict pre-spec edge before publication.

    Other prospective sources permit equal creation times. Statistical-use
    readback rejects equality, so accepting it here could strand a new spec.
    This pure relation neither authenticates the supplied record nor waits for
    a clock tick; the registrar supplies its already full-replayed source.
    """

    if type(record) is not ArtifactRecord:
        raise ExperimentError("reference-work chronology requires an exact statistical-use record")
    if _scientific_execution_timestamp(record.created_at, "statistical-use creation time") >= (
        _scientific_execution_timestamp(timestamp, "reference-work spec creation time")
    ):
        raise ExperimentError("statistical-use creation must strictly precede reference-work spec creation")


@dataclass(frozen=True, slots=True)
class ScientificMethodDefinitionBinding:
    """Fresh projection of one prospectively bound Method intention.

    The frozen run spec carries only the artifact and registry-record identity.
    Human-readable Method fields are always re-read from that exact frozen
    source; callers cannot supply them while constructing canonical state.
    This binding proves prospective intention provenance, not that executable
    code implements the intention.
    """

    method_definition_artifact_sha256: str
    method_definition_record_hash: str
    method_id: str
    name: str
    description: str
    assumptions: tuple[str, ...]
    component_ids: tuple[str, ...]
    profile: str = SCIENTIFIC_METHOD_DEFINITION_BINDING_PROFILE

    def __post_init__(self) -> None:
        validate_sha256(
            self.method_definition_artifact_sha256,
            "scientific Method-definition artifact SHA-256",
        )
        validate_sha256(
            self.method_definition_record_hash,
            "scientific Method-definition record hash",
        )
        validate_identifier(self.method_id, "scientific Method ID")
        for name in ("name", "description"):
            value = getattr(self, name)
            if (
                not isinstance(value, str)
                or not value.strip()
                or len(value) > 16 * 1024
                or "\x00" in value
            ):
                raise ExperimentError(f"scientific Method {name} is invalid")
        for name in ("assumptions", "component_ids"):
            values = getattr(self, name)
            if (
                not isinstance(values, tuple)
                or len(values) > MAX_ABLATIONS + 256
                or len(set(values)) != len(values)
            ):
                raise ExperimentError(
                    f"scientific Method {name} must be a bounded unique tuple"
                )
            for value in values:
                if name == "component_ids":
                    validate_identifier(value, "scientific Method component ID")
                elif (
                    not isinstance(value, str)
                    or not value.strip()
                    or len(value) > 16 * 1024
                    or "\x00" in value
                ):
                    raise ExperimentError(
                        "scientific Method assumption is invalid"
                    )
        if self.profile != SCIENTIFIC_METHOD_DEFINITION_BINDING_PROFILE:
            raise ExperimentError("scientific Method-definition profile is unsupported")


class ScientificExecutionVerificationStatus(StrEnum):
    VERIFIED = "VERIFIED"
    BLOCKED_EXTERNAL = "BLOCKED_EXTERNAL"
    UNSUPPORTED = "UNSUPPORTED"


class ScientificExecutionOutcome(StrEnum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    INVALID_OUTPUT = "INVALID_OUTPUT"
    CANCELLED = "CANCELLED"


class ScientificExecutionActivityKind(StrEnum):
    MODEL_INVOCATION = "MODEL_INVOCATION"
    PREDICTION_GENERATION = "PREDICTION_GENERATION"
    ABLATION_EXECUTION = "ABLATION_EXECUTION"
    DATASET_READ = "DATASET_READ"
    OUTPUT_COMMIT = "OUTPUT_COMMIT"
    EVALUATOR_QUERY = "EVALUATOR_QUERY"
    SELECTION_TRIAL = "SELECTION_TRIAL"
    ADAPTIVE_BRANCH = "ADAPTIVE_BRANCH"


class ScientificDatasetAccessPurpose(StrEnum):
    TRAIN_FEATURES = "TRAIN_FEATURES"
    TRAIN_LABELS = "TRAIN_LABELS"
    DEVELOPMENT_FEATURES = "DEVELOPMENT_FEATURES"
    DEVELOPMENT_LABELS = "DEVELOPMENT_LABELS"
    VALIDATION_FEATURES = "VALIDATION_FEATURES"
    VALIDATION_LABELS = "VALIDATION_LABELS"
    CONFIRMATORY_FEATURES = "CONFIRMATORY_FEATURES"
    CONFIRMATORY_LABELS = "CONFIRMATORY_LABELS"


class ScientificExecutionTerminalKind(StrEnum):
    ALL_PLANNED_WORK_COMPLETED = "ALL_PLANNED_WORK_COMPLETED"
    TIMEOUT = "TIMEOUT"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ExperimentPhase(StrEnum):
    EXPLORATORY = "EXPLORATORY"
    CONFIRMATORY = "CONFIRMATORY"


class EvidenceClass(StrEnum):
    """Declared eligibility of a run's outputs for scientific use.

    This declaration is necessary but never sufficient: only a successfully
    executed run whose captured output manifest passes every deterministic
    integrity check can become scientific evidence.  The conservative default
    keeps fixtures, smoke checks, and execution-boundary tests non-evidentiary
    unless a caller deliberately opts into scientific-result eligibility.
    """

    NON_EVIDENTIARY = "NON_EVIDENTIARY"
    SCIENTIFIC_RESULT_ELIGIBLE = "SCIENTIFIC_RESULT_ELIGIBLE"


class ExperimentClass(StrEnum):
    """Resource-planning classes required for ``LOCAL_MAC`` experiments."""

    SMOKE = "SMOKE"
    PILOT = "PILOT"
    EXPLORATORY = "EXPLORATORY"
    FINAL_LOCAL = "FINAL_LOCAL"


class RunState(StrEnum):
    SUBMITTED = "SUBMITTED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PREEMPTED = "PREEMPTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    INVALID_OUTPUT = "INVALID_OUTPUT"


class ValidationStatus(StrEnum):
    VALIDATED_LOCAL = "VALIDATED_LOCAL"
    UNTESTED = "UNTESTED"


class NetworkUseStatus(StrEnum):
    """Whether network use is known, rather than merely caller-reported."""

    USED = "USED"
    NOT_USED_ATTESTED = "NOT_USED_ATTESTED"
    UNKNOWN_UNATTESTED = "UNKNOWN_UNATTESTED"


class ComputeMode(StrEnum):
    LOCAL_MAC = "LOCAL_MAC"
    GPU_CLOUD = "GPU_CLOUD"


class LocalMacIsolationMode(StrEnum):
    """Whether the built-in local runner must use the reviewed macOS boundary."""

    DISABLED = "DISABLED"
    REQUIRED = "REQUIRED"


class LocalMacExecutionMode(StrEnum):
    """Immutable distinction between bound execution and injected diagnostics."""

    BOUND_BUILTIN = "BOUND_BUILTIN"
    INJECTED_DIAGNOSTIC = "INJECTED_DIAGNOSTIC"


class AcceleratorKind(StrEnum):
    CPU = "CPU"
    MPS = "MPS"
    CUDA = "CUDA"


class SchedulerKind(StrEnum):
    LOCAL = "LOCAL"
    DIRECT_REMOTE = "DIRECT_REMOTE"
    SCHEDULED = "SCHEDULED"
    SLURM = "SLURM"


class CachePolicy(StrEnum):
    DISABLED = "DISABLED"
    CONTENT_ADDRESSABLE = "CONTENT_ADDRESSABLE"


class CheckpointPolicy(StrEnum):
    DISABLED = "DISABLED"
    PER_SEED = "PER_SEED"
    PER_BATCH = "PER_BATCH"
    PERIODIC = "PERIODIC"


class SeedRunStatus(StrEnum):
    SUCCESS = "SUCCESS"
    NEGATIVE = "NEGATIVE"
    NULL = "NULL"
    FAILED = "FAILED"
    INVALID = "INVALID"


class ReproductionStatus(StrEnum):
    PASS = "PASS"
    OUTSIDE_TOLERANCE = "OUTSIDE_TOLERANCE"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    NON_EVIDENTIARY = "NON_EVIDENTIARY"


def _bounded_text(value: object, label: str, maximum_bytes: int = 4_096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExperimentError(f"{label} must be non-empty text")
    if len(value.encode("utf-8")) > maximum_bytes:
        raise ExperimentError(f"{label} exceeds size bound")
    return value


def _opaque_reference(value: object, label: str, maximum_bytes: int = 1_024) -> str:
    result = _bounded_text(value, label, maximum_bytes)
    if any(character in result for character in ("\x00", "\r", "\n")):
        raise ExperimentError(f"{label} contains a forbidden control character")
    return result


def _derive_network_use_status(
    network_used: object,
    network_isolation_attested: object,
) -> NetworkUseStatus:
    if not isinstance(network_used, bool):
        raise ExperimentError("network_used must be boolean")
    if not isinstance(network_isolation_attested, bool):
        raise ExperimentError("network isolation attestation marker must be boolean")
    if network_used and network_isolation_attested:
        raise ExperimentError("network use conflicts with a network-isolation attestation")
    if network_isolation_attested:
        raise ExperimentError(
            "network isolation requires registry-resolved backend attestation"
        )
    if network_used:
        return NetworkUseStatus.USED
    if network_isolation_attested:
        return NetworkUseStatus.NOT_USED_ATTESTED
    return NetworkUseStatus.UNKNOWN_UNATTESTED


def _relative_path(value: object, label: str, *, allow_dot: bool = False) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ExperimentError(f"{label} must be a project-relative path")
    path = PurePath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ExperimentError(f"{label} must be a project-relative path")
    normalized = Path(value).as_posix()
    if normalized in {"", "."} and not allow_dot:
        raise ExperimentError(f"{label} cannot name the project root")
    return normalized


def _finite_metric(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ExperimentError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ExperimentError(f"{label} must be finite")
    return result


@dataclass(frozen=True)
class ResourceEstimate:
    """Typed, provider-neutral estimate used before scheduling or escalation.

    The estimate records planning evidence only; it does not authorize compute
    escalation and it does not attest to resources actually consumed.
    """

    expected_scientific_value: float
    expected_uncertainty_reduction: float
    cpu_cores: int
    gpu_count: int
    ram_bytes: int
    vram_bytes: int
    disk_bytes: int
    wall_clock_seconds: float
    monetary_cost: float | None = None
    escalation_reason: str | None = None

    def __post_init__(self) -> None:
        for name in ("expected_scientific_value", "expected_uncertainty_reduction"):
            value = _finite_metric(getattr(self, name), name)
            if value < 0:
                raise ExperimentError(f"{name} must be non-negative")
            object.__setattr__(self, name, value)
        for name, maximum in (
            ("cpu_cores", MAX_COMPUTE_CONCURRENCY),
            ("gpu_count", 64),
            ("ram_bytes", MAX_COMPUTE_MEMORY_BYTES),
            ("vram_bytes", MAX_COMPUTE_MEMORY_BYTES),
            ("disk_bytes", MAX_COMPUTE_STORAGE_BYTES),
        ):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= maximum
            ):
                raise ExperimentError(f"{name} is outside its bounded range")
        if self.cpu_cores == 0 and self.gpu_count == 0:
            raise ExperimentError("resource estimate must request CPU or GPU compute")
        if self.ram_bytes == 0 or self.disk_bytes == 0:
            raise ExperimentError("resource estimate must include bounded RAM and disk")
        if (self.gpu_count == 0) != (self.vram_bytes == 0):
            raise ExperimentError("GPU count and VRAM estimate must be present together")
        wall_clock = _finite_metric(self.wall_clock_seconds, "wall_clock_seconds")
        if wall_clock <= 0:
            raise ExperimentError("wall_clock_seconds must be positive")
        object.__setattr__(self, "wall_clock_seconds", wall_clock)
        if self.monetary_cost is not None:
            cost = _finite_metric(self.monetary_cost, "monetary_cost")
            if cost < 0:
                raise ExperimentError("monetary_cost must be non-negative")
            object.__setattr__(self, "monetary_cost", cost)
        if self.escalation_reason is not None:
            object.__setattr__(
                self,
                "escalation_reason",
                _bounded_text(self.escalation_reason, "escalation_reason"),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "expected_scientific_value": self.expected_scientific_value,
            "expected_uncertainty_reduction": self.expected_uncertainty_reduction,
            "cpu_cores": self.cpu_cores,
            "gpu_count": self.gpu_count,
            "ram_bytes": self.ram_bytes,
            "vram_bytes": self.vram_bytes,
            "disk_bytes": self.disk_bytes,
            "wall_clock_seconds": self.wall_clock_seconds,
            "monetary_cost": self.monetary_cost,
            "escalation_reason": self.escalation_reason,
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_dict())).hexdigest()


@dataclass(frozen=True)
class ComputeProfile:
    """Provider-neutral, immutable execution profile.

    A profile describes admissible resources; it does not claim that hardware
    exists.  GPU profiles deliberately remain ``UNTESTED`` until a separate
    hardware validation artifact exists outside this offline boundary.
    """

    profile_id: str
    mode: ComputeMode
    accelerator: AcceleratorKind
    scheduler: SchedulerKind
    experiment_class: ExperimentClass
    cpu_cores: int
    accelerator_count: int
    memory_limit_bytes: int
    maximum_concurrency: int
    minimum_batch_size: int
    preferred_batch_size: int
    maximum_batch_size: int
    accelerator_memory_limit_bytes: int = 0
    disk_limit_bytes: int = 64 * 1024**3
    maximum_memory_fraction: float = 0.8
    supports_checkpointing: bool = True
    supports_preemption: bool = False
    validation_status: ValidationStatus = ValidationStatus.UNTESTED
    validation_artifact_sha256: str | None = None
    queue_name: str | None = None
    multi_accelerator_rationale: str | None = None
    hourly_cost: float | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.profile_id, "compute profile ID")
        for name, enum_type in (
            ("mode", ComputeMode),
            ("accelerator", AcceleratorKind),
            ("scheduler", SchedulerKind),
            ("experiment_class", ExperimentClass),
            ("validation_status", ValidationStatus),
        ):
            value = getattr(self, name)
            if not isinstance(value, enum_type):
                try:
                    object.__setattr__(self, name, enum_type(value))
                except (TypeError, ValueError) as exc:
                    raise ExperimentError(f"unknown {name}") from exc
        for name, minimum, maximum in (
            ("cpu_cores", 1, MAX_COMPUTE_CONCURRENCY),
            ("accelerator_count", 0, 64),
            ("memory_limit_bytes", 1, MAX_COMPUTE_MEMORY_BYTES),
            ("accelerator_memory_limit_bytes", 0, MAX_COMPUTE_MEMORY_BYTES),
            ("disk_limit_bytes", 1, MAX_COMPUTE_STORAGE_BYTES),
            ("maximum_concurrency", 1, MAX_COMPUTE_CONCURRENCY),
            ("minimum_batch_size", 1, MAX_BATCH_SIZE),
            ("preferred_batch_size", 1, MAX_BATCH_SIZE),
            ("maximum_batch_size", 1, MAX_BATCH_SIZE),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise ExperimentError(f"{name} is outside its bounded range")
        if self.maximum_concurrency > self.cpu_cores:
            raise ExperimentError("compute concurrency cannot exceed assigned CPU cores")
        if not (
            self.minimum_batch_size
            <= self.preferred_batch_size
            <= self.maximum_batch_size
        ):
            raise ExperimentError("compute batch-size bounds are inconsistent")
        fraction = _finite_metric(self.maximum_memory_fraction, "maximum_memory_fraction")
        if not 0 < fraction <= 0.95:
            raise ExperimentError("maximum_memory_fraction must be in (0, 0.95]")
        object.__setattr__(self, "maximum_memory_fraction", fraction)
        if not isinstance(self.supports_checkpointing, bool) or not isinstance(
            self.supports_preemption, bool
        ):
            raise ExperimentError("compute checkpoint/preemption flags must be boolean")
        if self.supports_preemption and not self.supports_checkpointing:
            raise ExperimentError("preemptible compute must support checkpoints")
        if self.validation_artifact_sha256 is not None:
            validate_sha256(
                self.validation_artifact_sha256,
                "compute validation artifact SHA-256",
            )
        if self.queue_name is not None:
            object.__setattr__(self, "queue_name", _bounded_text(self.queue_name, "queue name", 256))
        if self.multi_accelerator_rationale is not None:
            object.__setattr__(
                self,
                "multi_accelerator_rationale",
                _bounded_text(
                    self.multi_accelerator_rationale,
                    "multi-accelerator rationale",
                ),
            )
        if self.hourly_cost is not None:
            cost = _finite_metric(self.hourly_cost, "hourly_cost")
            if cost < 0:
                raise ExperimentError("hourly_cost must be non-negative")
            object.__setattr__(self, "hourly_cost", cost)

        if self.mode is ComputeMode.LOCAL_MAC:
            if self.scheduler is not SchedulerKind.LOCAL:
                raise ExperimentError("LOCAL_MAC requires the local scheduler")
            if self.accelerator not in {AcceleratorKind.CPU, AcceleratorKind.MPS}:
                raise ExperimentError("LOCAL_MAC supports only CPU or MPS")
            expected_count = 0 if self.accelerator is AcceleratorKind.CPU else 1
            if self.accelerator_count != expected_count:
                raise ExperimentError("LOCAL_MAC accelerator count is invalid")
            if self.accelerator_memory_limit_bytes != 0:
                raise ExperimentError("LOCAL_MAC uses bounded shared memory, not discrete VRAM")
            if self.validation_status is not ValidationStatus.VALIDATED_LOCAL:
                raise ExperimentError("LOCAL_MAC profiles require local validation status")
            if self.accelerator is AcceleratorKind.MPS and self.validation_artifact_sha256 is None:
                raise ExperimentError("MPS requires a bound validation artifact")
            if self.queue_name is not None or self.supports_preemption:
                raise ExperimentError("LOCAL_MAC cannot claim a remote queue or preemption")
        else:
            if self.accelerator is not AcceleratorKind.CUDA or self.accelerator_count < 1:
                raise ExperimentError("GPU_CLOUD requires one or more CUDA accelerators")
            if self.accelerator_memory_limit_bytes == 0:
                raise ExperimentError("GPU_CLOUD requires a bounded VRAM allocation")
            if self.scheduler is SchedulerKind.LOCAL:
                raise ExperimentError("GPU_CLOUD cannot use the local scheduler")
            if self.validation_status is not ValidationStatus.UNTESTED:
                raise ExperimentError("GPU_CLOUD remains UNTESTED without real infrastructure")
            if self.scheduler in {SchedulerKind.SCHEDULED, SchedulerKind.SLURM} and self.queue_name is None:
                raise ExperimentError("scheduled GPU_CLOUD profiles require a queue name")
            if self.accelerator_count > 1 and self.multi_accelerator_rationale is None:
                raise ExperimentError("multi-GPU use requires a scientific/resource rationale")

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "mode": self.mode.value,
            "accelerator": self.accelerator.value,
            "scheduler": self.scheduler.value,
            "experiment_class": self.experiment_class.value,
            "cpu_cores": self.cpu_cores,
            "accelerator_count": self.accelerator_count,
            "memory_limit_bytes": self.memory_limit_bytes,
            "accelerator_memory_limit_bytes": self.accelerator_memory_limit_bytes,
            "disk_limit_bytes": self.disk_limit_bytes,
            "maximum_concurrency": self.maximum_concurrency,
            "minimum_batch_size": self.minimum_batch_size,
            "preferred_batch_size": self.preferred_batch_size,
            "maximum_batch_size": self.maximum_batch_size,
            "maximum_memory_fraction": self.maximum_memory_fraction,
            "supports_checkpointing": self.supports_checkpointing,
            "supports_preemption": self.supports_preemption,
            "validation_status": self.validation_status.value,
            "validation_artifact_sha256": self.validation_artifact_sha256,
            "queue_name": self.queue_name,
            "multi_accelerator_rationale": self.multi_accelerator_rationale,
            "hourly_cost": self.hourly_cost,
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_dict())).hexdigest()


def default_local_cpu_profile() -> ComputeProfile:
    return ComputeProfile(
        profile_id="local-mac-cpu-default",
        mode=ComputeMode.LOCAL_MAC,
        accelerator=AcceleratorKind.CPU,
        scheduler=SchedulerKind.LOCAL,
        experiment_class=ExperimentClass.SMOKE,
        cpu_cores=1,
        accelerator_count=0,
        memory_limit_bytes=2 * 1024**3,
        maximum_concurrency=1,
        minimum_batch_size=1,
        preferred_batch_size=16,
        maximum_batch_size=64,
        validation_status=ValidationStatus.VALIDATED_LOCAL,
    )


def default_resource_estimate() -> ResourceEstimate:
    return ResourceEstimate(
        expected_scientific_value=0.0,
        expected_uncertainty_reduction=0.0,
        cpu_cores=1,
        gpu_count=0,
        ram_bytes=512 * 1024**2,
        vram_bytes=0,
        disk_bytes=64 * 1024**2,
        wall_clock_seconds=1.0,
        monetary_cost=0.0,
    )


@dataclass(frozen=True)
class AdaptiveExecutionPlan:
    profile_sha256: str
    usable_memory_bytes: int
    memory_limit_per_worker_bytes: int
    concurrency: int
    batch_size: int
    cache_key: str
    estimated_wall_clock_seconds: float
    estimated_monetary_cost: float | None

    def __post_init__(self) -> None:
        validate_sha256(self.profile_sha256, "adaptive-plan profile SHA-256")
        validate_sha256(self.cache_key, "adaptive-plan cache key")
        for name in (
            "usable_memory_bytes",
            "memory_limit_per_worker_bytes",
            "concurrency",
            "batch_size",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ExperimentError(f"adaptive-plan {name} must be positive")
        wall = _finite_metric(self.estimated_wall_clock_seconds, "estimated wall clock")
        if wall <= 0:
            raise ExperimentError("estimated wall clock must be positive")
        object.__setattr__(self, "estimated_wall_clock_seconds", wall)
        if self.estimated_monetary_cost is not None:
            cost = _finite_metric(self.estimated_monetary_cost, "estimated monetary cost")
            if cost < 0:
                raise ExperimentError("estimated monetary cost must be non-negative")
            object.__setattr__(self, "estimated_monetary_cost", cost)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_sha256": self.profile_sha256,
            "usable_memory_bytes": self.usable_memory_bytes,
            "memory_limit_per_worker_bytes": self.memory_limit_per_worker_bytes,
            "concurrency": self.concurrency,
            "batch_size": self.batch_size,
            "cache_key": self.cache_key,
            "estimated_wall_clock_seconds": self.estimated_wall_clock_seconds,
            "estimated_monetary_cost": self.estimated_monetary_cost,
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_dict())).hexdigest()

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AdaptiveExecutionPlan":
        expected = {
            "profile_sha256",
            "usable_memory_bytes",
            "memory_limit_per_worker_bytes",
            "concurrency",
            "batch_size",
            "cache_key",
            "estimated_wall_clock_seconds",
            "estimated_monetary_cost",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ExperimentError("persisted execution plan has unexpected fields")
        try:
            return cls(**{name: value[name] for name in expected})
        except TypeError as exc:
            raise ExperimentError("persisted execution plan is malformed") from exc


def _validate_adaptive_plan_binding(
    plan: AdaptiveExecutionPlan,
    profile: ComputeProfile,
    estimate: ResourceEstimate,
    *,
    pending_tasks: int,
    bytes_per_sample: int,
    worker_overhead_bytes: int,
) -> None:
    if plan.profile_sha256 != profile.sha256:
        raise ExperimentIntegrityError("persisted execution plan changed compute profile")
    if (
        plan.usable_memory_bytes > profile.memory_limit_bytes
        or plan.concurrency > min(profile.maximum_concurrency, pending_tasks)
        or not profile.minimum_batch_size <= plan.batch_size <= profile.maximum_batch_size
        or plan.memory_limit_per_worker_bytes
        != plan.usable_memory_bytes // plan.concurrency
        or worker_overhead_bytes + bytes_per_sample * plan.batch_size
        > plan.memory_limit_per_worker_bytes
    ):
        raise ExperimentIntegrityError("persisted execution plan exceeds frozen resource bounds")
    expected_cache_key = hashlib.sha256(
        canonical_json_bytes(
            {
                "profile_sha256": profile.sha256,
                "estimate_sha256": estimate.sha256,
                "usable_memory_bytes": plan.usable_memory_bytes,
                "concurrency": plan.concurrency,
                "batch_size": plan.batch_size,
            }
        )
    ).hexdigest()
    if plan.cache_key != expected_cache_key:
        raise ExperimentIntegrityError("persisted execution plan cache binding changed")
    expected_wall = estimate.wall_clock_seconds / plan.concurrency
    if plan.estimated_wall_clock_seconds != expected_wall:
        raise ExperimentIntegrityError("persisted execution plan wall-clock estimate changed")
    expected_cost = estimate.monetary_cost
    if expected_cost is None and profile.hourly_cost is not None:
        expected_cost = profile.hourly_cost * expected_wall / 3600.0
    if plan.estimated_monetary_cost != expected_cost:
        raise ExperimentIntegrityError("persisted execution plan cost estimate changed")


def plan_adaptive_execution(
    profile: ComputeProfile,
    estimate: ResourceEstimate,
    *,
    observed_available_memory_bytes: int,
    pending_tasks: int,
    bytes_per_sample: int,
    worker_overhead_bytes: int,
    concurrency_cap: int | None = None,
) -> AdaptiveExecutionPlan:
    """Deterministically choose memory, concurrency, and batch size."""

    if not isinstance(profile, ComputeProfile) or not isinstance(estimate, ResourceEstimate):
        raise ExperimentError("adaptive planning requires typed profile and estimate")
    expected_gpu_count = profile.accelerator_count if profile.mode is ComputeMode.GPU_CLOUD else 0
    if estimate.cpu_cores > profile.cpu_cores or estimate.gpu_count != expected_gpu_count:
        raise ExperimentError("resource estimate exceeds the compute profile")
    if estimate.ram_bytes > profile.memory_limit_bytes:
        raise ExperimentError("resource estimate exceeds the compute-profile memory")
    if estimate.vram_bytes > profile.accelerator_memory_limit_bytes:
        raise ExperimentError("resource estimate exceeds compute-profile accelerator memory")
    if estimate.disk_bytes > profile.disk_limit_bytes:
        raise ExperimentError("resource estimate exceeds the compute-profile disk")
    for name, value, maximum in (
        ("observed_available_memory_bytes", observed_available_memory_bytes, MAX_COMPUTE_MEMORY_BYTES),
        ("pending_tasks", pending_tasks, MAX_RUN_SEEDS),
        ("bytes_per_sample", bytes_per_sample, MAX_COMPUTE_MEMORY_BYTES),
        ("worker_overhead_bytes", worker_overhead_bytes, MAX_COMPUTE_MEMORY_BYTES),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
            raise ExperimentError(f"{name} is outside its bounded range")
    if concurrency_cap is None:
        concurrency_cap = profile.maximum_concurrency
    if (
        isinstance(concurrency_cap, bool)
        or not isinstance(concurrency_cap, int)
        or not 1 <= concurrency_cap <= MAX_COMPUTE_CONCURRENCY
    ):
        raise ExperimentError("concurrency cap is invalid")
    usable = min(
        profile.memory_limit_bytes,
        int(observed_available_memory_bytes * profile.maximum_memory_fraction),
    )
    minimum_worker = worker_overhead_bytes + bytes_per_sample * profile.minimum_batch_size
    affordable_workers = usable // minimum_worker
    concurrency = min(
        profile.maximum_concurrency,
        concurrency_cap,
        pending_tasks,
        affordable_workers,
    )
    if concurrency < 1:
        raise ExperimentError("available memory cannot support the minimum local batch")
    per_worker = usable // concurrency
    affordable_batch = (per_worker - worker_overhead_bytes) // bytes_per_sample
    batch_size = min(profile.preferred_batch_size, profile.maximum_batch_size, affordable_batch)
    if batch_size < profile.minimum_batch_size:
        raise ExperimentError("adaptive batch sizing fell below the frozen minimum")
    effective_wall = estimate.wall_clock_seconds / concurrency
    cost = estimate.monetary_cost
    if cost is None and profile.hourly_cost is not None:
        cost = profile.hourly_cost * effective_wall / 3600.0
    cache_key = hashlib.sha256(
        canonical_json_bytes(
            {
                "profile_sha256": profile.sha256,
                "estimate_sha256": estimate.sha256,
                "usable_memory_bytes": usable,
                "concurrency": concurrency,
                "batch_size": batch_size,
            }
        )
    ).hexdigest()
    return AdaptiveExecutionPlan(
        profile_sha256=profile.sha256,
        usable_memory_bytes=usable,
        memory_limit_per_worker_bytes=per_worker,
        concurrency=concurrency,
        batch_size=batch_size,
        cache_key=cache_key,
        estimated_wall_clock_seconds=effective_wall,
        estimated_monetary_cost=cost,
    )


@dataclass(frozen=True)
class EscalationDecision:
    decision_id: str
    source_profile_sha256: str
    target_profile_sha256: str
    target_estimate_sha256: str
    rationale: str
    scientific_equivalence_rationale: str
    expected_information_gain: float
    lower_cost_alternatives_exhausted: bool
    external_validation: ValidationStatus = ValidationStatus.UNTESTED

    def __post_init__(self) -> None:
        validate_identifier(self.decision_id, "escalation decision ID")
        for value, label in (
            (self.source_profile_sha256, "source profile SHA-256"),
            (self.target_profile_sha256, "target profile SHA-256"),
            (self.target_estimate_sha256, "target estimate SHA-256"),
        ):
            validate_sha256(value, label)
        object.__setattr__(self, "rationale", _bounded_text(self.rationale, "escalation rationale"))
        object.__setattr__(
            self,
            "scientific_equivalence_rationale",
            _bounded_text(
                self.scientific_equivalence_rationale,
                "scientific equivalence rationale",
            ),
        )
        information_gain = _finite_metric(
            self.expected_information_gain,
            "expected information gain",
        )
        if information_gain <= 0:
            raise ExperimentError("GPU escalation requires positive expected information gain")
        object.__setattr__(self, "expected_information_gain", information_gain)
        if self.lower_cost_alternatives_exhausted is not True:
            raise ExperimentError("GPU escalation must document cheaper alternatives")
        if self.external_validation is not ValidationStatus.UNTESTED:
            raise ExperimentError("GPU escalation remains externally UNTESTED")

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "source_profile_sha256": self.source_profile_sha256,
            "target_profile_sha256": self.target_profile_sha256,
            "target_estimate_sha256": self.target_estimate_sha256,
            "rationale": self.rationale,
            "scientific_equivalence_rationale": self.scientific_equivalence_rationale,
            "expected_information_gain": self.expected_information_gain,
            "lower_cost_alternatives_exhausted": self.lower_cost_alternatives_exhausted,
            "external_validation": self.external_validation.value,
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_dict())).hexdigest()


@dataclass(frozen=True)
class ComputeEscalationBudget:
    """Frozen monetary ceiling for one exact target profile and estimate."""

    budget_id: str
    target_profile_sha256: str
    target_estimate_sha256: str
    maximum_monetary_cost: float
    maximum_total_attempts: int = 1
    maximum_cumulative_monetary_cost: float | None = None
    maximum_cumulative_wall_clock_seconds: float = 86_400.0
    currency: str = "USD"

    def __post_init__(self) -> None:
        validate_identifier(self.budget_id, "compute escalation budget ID")
        validate_sha256(
            self.target_profile_sha256,
            "compute escalation budget target-profile SHA-256",
        )
        validate_sha256(
            self.target_estimate_sha256,
            "compute escalation budget target-estimate SHA-256",
        )
        maximum = _finite_metric(
            self.maximum_monetary_cost,
            "compute escalation maximum monetary cost",
        )
        if maximum < 0:
            raise ExperimentError(
                "compute escalation maximum monetary cost must be non-negative"
            )
        object.__setattr__(self, "maximum_monetary_cost", maximum)
        if (
            isinstance(self.maximum_total_attempts, bool)
            or not isinstance(self.maximum_total_attempts, int)
            or not 1 <= self.maximum_total_attempts <= 64
        ):
            raise ExperimentError(
                "compute escalation attempt ceiling must be between 1 and 64"
            )
        cumulative_monetary = (
            maximum
            if self.maximum_cumulative_monetary_cost is None
            else _finite_metric(
                self.maximum_cumulative_monetary_cost,
                "compute escalation cumulative monetary ceiling",
            )
        )
        cumulative_wall = _finite_metric(
            self.maximum_cumulative_wall_clock_seconds,
            "compute escalation cumulative wall-clock ceiling",
        )
        if cumulative_monetary < maximum or cumulative_wall <= 0:
            raise ExperimentError(
                "compute escalation cumulative ceilings are invalid"
            )
        object.__setattr__(
            self,
            "maximum_cumulative_monetary_cost",
            cumulative_monetary,
        )
        object.__setattr__(
            self,
            "maximum_cumulative_wall_clock_seconds",
            cumulative_wall,
        )
        if self.currency != "USD":
            raise ExperimentError(
                "compute escalation budget currently requires explicit USD units"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "budget_id": self.budget_id,
            "target_profile_sha256": self.target_profile_sha256,
            "target_estimate_sha256": self.target_estimate_sha256,
            "maximum_monetary_cost": self.maximum_monetary_cost,
            "maximum_total_attempts": self.maximum_total_attempts,
            "maximum_cumulative_monetary_cost": (
                self.maximum_cumulative_monetary_cost
            ),
            "maximum_cumulative_wall_clock_seconds": (
                self.maximum_cumulative_wall_clock_seconds
            ),
            "currency": self.currency,
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_dict())).hexdigest()


@dataclass(frozen=True)
class FrozenRunSpec:
    """Immutable scientific and execution identity for exactly one attempt."""

    run_id: str
    experiment_id: str
    hypothesis_id: str
    phase: ExperimentPhase
    argv: tuple[str, ...]
    working_directory: str
    code_sha256: str
    data_sha256: str
    configuration_sha256: str
    evaluator_sha256: str
    seeds: tuple[int, ...]
    comparison_tolerance: float = 0.0
    timeout_seconds: float = 3_600.0
    maximum_stdout_bytes: int = DEFAULT_MAX_LOG_BYTES
    maximum_stderr_bytes: int = DEFAULT_MAX_LOG_BYTES
    required_ablations: tuple[str, ...] = ()
    attempt: int = 1
    retry_of_run_id: str | None = None
    network_allowed: bool = False
    shell_allowed: bool = False
    evidence_class: EvidenceClass = EvidenceClass.NON_EVIDENTIARY
    scientific_purpose: str = "execute the frozen hypothesis under the bound evaluator"
    expected_outputs: tuple[str, ...] = ("output_manifest",)
    seed_policy: str = "EXPLICIT_FIXED_SEEDS_NO_SELECTION"
    termination_conditions: tuple[str, ...] = (
        "wall_clock_timeout",
        "all_planned_seeds_reported",
    )
    compute_profile: ComputeProfile = field(default_factory=default_local_cpu_profile)
    resource_estimate: ResourceEstimate = field(default_factory=default_resource_estimate)
    cache_policy: CachePolicy = CachePolicy.CONTENT_ADDRESSABLE
    checkpoint_policy: CheckpointPolicy = CheckpointPolicy.PER_SEED
    bytes_per_sample: int = 1024 * 1024
    worker_overhead_bytes: int = 64 * 1024 * 1024
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        validate_identifier(self.run_id, "run ID")
        validate_identifier(self.experiment_id, "experiment ID")
        validate_identifier(self.hypothesis_id, "hypothesis ID")
        if not isinstance(self.phase, ExperimentPhase):
            try:
                object.__setattr__(self, "phase", ExperimentPhase(self.phase))
            except (TypeError, ValueError) as exc:
                raise ExperimentError("unknown experiment phase") from exc
        if not isinstance(self.argv, tuple):
            object.__setattr__(self, "argv", tuple(self.argv))
        if (
            not self.argv
            or any(
                not isinstance(item, str)
                or not item
                or "\x00" in item
                or "\n" in item
                or "\r" in item
                for item in self.argv
            )
        ):
            raise ExperimentError("argv must be an explicit non-empty string tuple")
        object.__setattr__(
            self,
            "working_directory",
            _relative_path(self.working_directory, "working_directory", allow_dot=True),
        )
        validate_sha256(self.code_sha256, "code SHA-256")
        validate_sha256(self.data_sha256, "data SHA-256")
        validate_sha256(self.configuration_sha256, "configuration SHA-256")
        validate_sha256(self.evaluator_sha256, "evaluator SHA-256")
        if not isinstance(self.seeds, tuple):
            object.__setattr__(self, "seeds", tuple(self.seeds))
        if not self.seeds or len(self.seeds) > MAX_RUN_SEEDS:
            raise ExperimentError("seeds must be a bounded non-empty tuple")
        if any(isinstance(seed, bool) or not isinstance(seed, int) or seed < 0 for seed in self.seeds):
            raise ExperimentError("seeds must be non-negative integers")
        if len(set(self.seeds)) != len(self.seeds):
            raise ExperimentError("seeds must be unique")
        object.__setattr__(
            self,
            "comparison_tolerance",
            _finite_metric(self.comparison_tolerance, "comparison_tolerance"),
        )
        if self.comparison_tolerance < 0:
            raise ExperimentError("comparison_tolerance must be non-negative")
        object.__setattr__(self, "timeout_seconds", _finite_metric(self.timeout_seconds, "timeout_seconds"))
        if self.timeout_seconds <= 0:
            raise ExperimentError("timeout_seconds must be positive")
        for name in ("maximum_stdout_bytes", "maximum_stderr_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= 64 * 1024 * 1024:
                raise ExperimentError(f"{name} must be a positive bounded integer")
        if not isinstance(self.required_ablations, tuple):
            object.__setattr__(self, "required_ablations", tuple(self.required_ablations))
        if len(self.required_ablations) > MAX_ABLATIONS:
            raise ExperimentError("required ablations exceed safety bound")
        for item in self.required_ablations:
            validate_identifier(item, "ablation ID")
        if len(set(self.required_ablations)) != len(self.required_ablations):
            raise ExperimentError("required ablations must be unique")
        if isinstance(self.attempt, bool) or not isinstance(self.attempt, int) or self.attempt < 1:
            raise ExperimentError("attempt must be a positive integer")
        if self.retry_of_run_id is not None:
            validate_identifier(self.retry_of_run_id, "retry run ID")
            if self.retry_of_run_id == self.run_id:
                raise ExperimentError("retry must use a new run identity")
        if self.phase == ExperimentPhase.CONFIRMATORY and (
            self.attempt != 1 or self.retry_of_run_id is not None
        ):
            raise ConfirmatoryPolicyError("confirmatory runs cannot be silently retried")
        if self.phase == ExperimentPhase.EXPLORATORY:
            if self.attempt == 1 and self.retry_of_run_id is not None:
                raise ExperimentError("first exploratory attempt cannot name retry_of_run_id")
            if self.attempt > 1 and self.retry_of_run_id is None:
                raise ExperimentError("exploratory retry must name retry_of_run_id")
        if self.network_allowed is not False:
            raise ExperimentError("experiment command network access is forbidden")
        if self.shell_allowed is not False:
            raise ExperimentError("shell execution is forbidden")
        if not isinstance(self.evidence_class, EvidenceClass):
            try:
                object.__setattr__(self, "evidence_class", EvidenceClass(self.evidence_class))
            except (TypeError, ValueError) as exc:
                raise ExperimentError("unknown evidence class") from exc
        object.__setattr__(
            self,
            "scientific_purpose",
            _bounded_text(self.scientific_purpose, "scientific purpose", 16 * 1024),
        )
        for name, values, maximum in (
            ("expected_outputs", self.expected_outputs, 256),
            ("termination_conditions", self.termination_conditions, 256),
        ):
            if not isinstance(values, tuple):
                values = tuple(values)
                object.__setattr__(self, name, values)
            if not values or len(values) > maximum:
                raise ExperimentError(f"{name} must be a bounded non-empty tuple")
            for value in values:
                validate_identifier(value, name)
            if len(set(values)) != len(values):
                raise ExperimentError(f"{name} must be unique")
        object.__setattr__(self, "seed_policy", _bounded_text(self.seed_policy, "seed policy"))
        if not isinstance(self.compute_profile, ComputeProfile):
            raise ExperimentError("compute_profile must be typed")
        if not isinstance(self.resource_estimate, ResourceEstimate):
            raise ExperimentError("resource_estimate must be typed")
        expected_gpu_count = (
            self.compute_profile.accelerator_count
            if self.compute_profile.mode is ComputeMode.GPU_CLOUD
            else 0
        )
        if self.resource_estimate.gpu_count != expected_gpu_count:
            raise ExperimentError("resource estimate GPU count differs from compute profile")
        if self.resource_estimate.cpu_cores > self.compute_profile.cpu_cores:
            raise ExperimentError("resource estimate exceeds compute-profile CPU cores")
        if self.resource_estimate.ram_bytes > self.compute_profile.memory_limit_bytes:
            raise ExperimentError("resource estimate exceeds compute-profile memory")
        if (
            self.resource_estimate.vram_bytes
            > self.compute_profile.accelerator_memory_limit_bytes
        ):
            raise ExperimentError("resource estimate exceeds compute-profile accelerator memory")
        if self.resource_estimate.disk_bytes > self.compute_profile.disk_limit_bytes:
            raise ExperimentError("resource estimate exceeds compute-profile disk")
        if self.resource_estimate.wall_clock_seconds > self.timeout_seconds:
            raise ExperimentError("resource estimate exceeds the run timeout")
        if (
            self.resource_estimate.monetary_cost is None
            and self.compute_profile.hourly_cost is None
        ):
            raise ExperimentError("run requires an explicit or profile-derived cost estimate")
        for name, enum_type in (
            ("cache_policy", CachePolicy),
            ("checkpoint_policy", CheckpointPolicy),
        ):
            value = getattr(self, name)
            if not isinstance(value, enum_type):
                try:
                    object.__setattr__(self, name, enum_type(value))
                except (TypeError, ValueError) as exc:
                    raise ExperimentError(f"unknown {name}") from exc
        if (
            self.checkpoint_policy is not CheckpointPolicy.DISABLED
            and not self.compute_profile.supports_checkpointing
        ):
            raise ExperimentError("checkpoint policy requires profile checkpoint support")
        if (
            self.compute_profile.supports_preemption
            and self.checkpoint_policy is CheckpointPolicy.DISABLED
        ):
            raise ExperimentError("preemptible profiles require a checkpoint policy")
        for name in ("bytes_per_sample", "worker_overhead_bytes"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= MAX_COMPUTE_MEMORY_BYTES
            ):
                raise ExperimentError(f"{name} is outside its bounded range")
        if not isinstance(self.metadata, Mapping):
            raise ExperimentError("run metadata must be a mapping")
        object.__setattr__(self, "metadata", freeze_json(dict(self.metadata)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "SCIENTIST_ONE_FROZEN_RUN_SPEC_V1",
            "run_id": self.run_id,
            "experiment_id": self.experiment_id,
            "hypothesis_id": self.hypothesis_id,
            "phase": self.phase.value,
            "argv": list(self.argv),
            "working_directory": self.working_directory,
            "code_sha256": self.code_sha256,
            "data_sha256": self.data_sha256,
            "configuration_sha256": self.configuration_sha256,
            "evaluator_sha256": self.evaluator_sha256,
            "seeds": list(self.seeds),
            "comparison_tolerance": self.comparison_tolerance,
            "timeout_seconds": self.timeout_seconds,
            "maximum_stdout_bytes": self.maximum_stdout_bytes,
            "maximum_stderr_bytes": self.maximum_stderr_bytes,
            "required_ablations": list(self.required_ablations),
            "attempt": self.attempt,
            "retry_of_run_id": self.retry_of_run_id,
            "network_allowed": False,
            "shell_allowed": False,
            "evidence_class": self.evidence_class.value,
            "scientific_purpose": self.scientific_purpose,
            "expected_outputs": list(self.expected_outputs),
            "seed_policy": self.seed_policy,
            "termination_conditions": list(self.termination_conditions),
            "compute_profile": self.compute_profile.to_dict(),
            "resource_estimate": self.resource_estimate.to_dict(),
            "cache_policy": self.cache_policy.value,
            "checkpoint_policy": self.checkpoint_policy.value,
            "bytes_per_sample": self.bytes_per_sample,
            "worker_overhead_bytes": self.worker_overhead_bytes,
            "metadata": thaw_json(self.metadata),
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_dict())).hexdigest()

    @property
    def scientific_binding_sha256(self) -> str:
        # Derive this from the complete serialized contract so future
        # result-affecting fields cannot be accidentally omitted.  Only the
        # per-attempt identity and explicit retry lineage are excluded; clean
        # reruns and explicit exploratory retries necessarily change those.
        payload = self.to_dict()
        for lineage_field in ("run_id", "attempt", "retry_of_run_id"):
            del payload[lineage_field]
        return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()

    @property
    def project_definition_sha256(self) -> str:
        """Provider-neutral scientific identity used for compute escalation."""

        payload = self.to_dict()
        for execution_field in (
            "run_id",
            "argv",
            "working_directory",
            "timeout_seconds",
            "maximum_stdout_bytes",
            "maximum_stderr_bytes",
            "attempt",
            "retry_of_run_id",
            "compute_profile",
            "resource_estimate",
            "cache_policy",
            "checkpoint_policy",
            "bytes_per_sample",
            "worker_overhead_bytes",
        ):
            del payload[execution_field]
        return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _scientific_statistical_use_context(
    registry: ArtifactRegistry,
    spec: FrozenRunSpec,
) -> tuple[EventLedger, str, str, str] | None:
    """Select only the exact co-rooted ledger, never grant source authority."""

    if type(registry) is not ArtifactRegistry or type(spec) is not FrozenRunSpec:
        raise ExperimentError("statistical-use binding requires exact registry and spec")
    metadata = thaw_json(spec.metadata)
    if SCIENTIFIC_STATISTICAL_USE_BINDING_METADATA_KEY not in metadata:
        return None
    value = metadata[SCIENTIFIC_STATISTICAL_USE_BINDING_METADATA_KEY]
    if (
        not isinstance(value, Mapping)
        or set(value) != {
            "schema_version", "profile_id", "ledger_run_id",
            "statistical_use_authority_artifact_sha256",
            "statistical_use_authority_record_hash",
        }
        or value["schema_version"] != SCIENTIFIC_STATISTICAL_USE_BINDING_SCHEMA
        or value["profile_id"] != BOUNDED_MEAN_PROFILE_ID
    ):
        raise ExperimentError("statistical-use spec binding is malformed or unsupported")
    run_id = validate_identifier(value["ledger_run_id"], "statistical-use ledger run ID")
    digest = value["statistical_use_authority_artifact_sha256"]
    record_hash = value["statistical_use_authority_record_hash"]
    validate_sha256(digest, "statistical-use authority artifact SHA-256")
    validate_sha256(record_hash, "statistical-use authority record hash")
    # Validate the namespace before constructing even a read-only ledger.
    # Execution run identity is deliberately not used to choose this path.
    if registry.base_path.as_posix() != f"runs/{run_id}/registry":
        raise ExperimentError("statistical-use binding names another run registry")
    ledger = EventLedger(registry.policy.root, f"runs/{run_id}/events.jsonl")
    from .research_state import _require_run_scoped_authority_paths

    _require_run_scoped_authority_paths(registry, ledger, run_id=run_id)
    return ledger, run_id, digest, record_hash


def resolve_scientific_statistical_use_binding(
    registry: ArtifactRegistry,
    *,
    spec: FrozenRunSpec,
    expected_contract_artifact_sha256: str,
) -> DatasetStatisticalUseAuthority | None:
    """Freshly replay prospective statistical use and its exact Dataset input.

    An absent binding preserves historical contracts, but cannot downgrade a
    new bounded-mean contract.  The statistical-use reverse spec inventory is
    metadata/chronology-only: this resolver never requests a freeze receipt
    while the design freeze itself is being established.
    """

    context = _scientific_statistical_use_context(registry, spec)
    validate_sha256(expected_contract_artifact_sha256, "statistical-use contract SHA-256")
    from .scientific_design import require_frozen_evaluation_contract

    if context is not None:
        ledger, run_id, digest, record_hash = context
        before = _locked_scientific_execution_snapshot(registry, ledger, run_id)
    contract = require_frozen_evaluation_contract(
        registry, contract_artifact_sha256=expected_contract_artifact_sha256,
    )
    requires_binding = (
        any(policy.rule_id == BOUNDED_MEAN_DECISION_RULE_ID
            for policy in contract.hypothesis_evaluation_policies)
        or contract.statistical_plan.primary_test == BOUNDED_MEAN_ZERO_P_METHOD_ID
        or contract.statistical_plan.confidence_interval == BOUNDED_MEAN_INTERVAL_METHOD_ID
    )
    if context is None:
        if requires_binding:
            raise ExperimentError("bounded-mean contract requires its prospective statistical-use binding")
        return None
    from .dataset_statistical_use import require_dataset_statistical_use_authority
    from .research_state import require_scientific_experiment_dataset_projection

    authority = require_dataset_statistical_use_authority(
        registry, ledger, run_id=run_id, authority_artifact_hash=digest,
    )
    if (
        not requires_binding
        or authority.artifact_hash != digest
        or authority.record_hash != record_hash
        or authority.run_id != run_id
        or authority.profile_id != BOUNDED_MEAN_PROFILE_ID
        or authority.evaluation_contract_artifact_hash != expected_contract_artifact_sha256
        or authority.dataset_id != contract.dataset.dataset_id
        or authority.seed_order != spec.seeds
        or spec.seeds != contract.seed_reporting.seeds
        or spec.phase is not ExperimentPhase.CONFIRMATORY
        or spec.hypothesis_id != contract.hypothesis_register.primary.hypothesis_id
        or spec.experiment_id != contract.hypothesis_register.primary.planned_experiment
        or spec.metadata.get("evaluation_split") != contract.dataset.confirmatory_split_id
    ):
        raise ExperimentError("statistical-use authority differs from exact frozen execution context")
    policy = contract.hypothesis_evaluation_policy(spec.hypothesis_id)
    expected_plan = BoundedMeanInferencePlan(
        alpha=policy.alpha,
        benefit_margin=policy.meaningful_effect,
        harm_margin=policy.falsification_effect,
        minimum_unit_count=policy.minimum_sample_size,
        unit_ids=authority.member_unit_ids,
        seed_order=spec.seeds,
    )
    if (
        policy.rule_id != BOUNDED_MEAN_DECISION_RULE_ID
        or type(authority.bounded_mean_plan) is not BoundedMeanInferencePlan
        or authority.bounded_mean_plan != expected_plan
    ):
        raise ExperimentError("statistical-use numerical plan differs from exact frozen policy")
    require_scientific_experiment_dataset_projection(
        registry, ledger, run_id=run_id, projection_artifact_hash=spec.data_sha256,
        expected_dataset_authority_artifact_hash=authority.dataset_authority_artifact_hash,
        expected_evaluation_contract_artifact_hash=expected_contract_artifact_sha256,
    )
    _require_scientific_execution_snapshot_unchanged(
        registry, ledger, run_id, *before,
    )
    return authority


def resolve_scientific_reference_work_binding(
    registry: ArtifactRegistry,
    *,
    spec: FrozenRunSpec,
    expected_contract_artifact_sha256: str,
) -> ScientificReferenceWorkBinding | None:
    """Replay the optional fixed-model reference-work declaration upstream only.

    The ordinary statistical-use owner supplies the exact co-rooted ledger
    and reviewed partition. No projection output, execution, domain receipt,
    Result or execution-admissibility owner is needed before design freeze.
    This is a prospective workload/common-run-cap binding, not proof that an
    execution happened or used equal time, memory, energy or training effort.
    """

    if type(registry) is not ArtifactRegistry or type(spec) is not FrozenRunSpec:
        raise ExperimentError("reference-work binding requires exact registry and spec")
    metadata = thaw_json(spec.metadata)
    if SCIENTIFIC_REFERENCE_WORK_POLICY_METADATA_KEY not in metadata:
        return None
    from .generic_ml_projection import (
        GENERIC_ML_COMPARISON_SCOPE,
        GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
        GENERIC_ML_POLICY_SCHEMA,
        GENERIC_ML_ROBUSTNESS_TEST_ID,
        derive_frozen_model_reference_work,
        parse_generic_ml_reference_work_policy,
        require_generic_ml_reference_work_wall_cap,
    )

    policy = parse_generic_ml_reference_work_policy(
        metadata[SCIENTIFIC_REFERENCE_WORK_POLICY_METADATA_KEY]
    )
    context = _scientific_statistical_use_context(registry, spec)
    if context is None:
        raise ExperimentError("reference-work policy requires its prospective statistical-use binding")
    if (
        spec.evidence_class is not EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE
        or spec.phase is not ExperimentPhase.CONFIRMATORY
        or spec.network_allowed is not False
        or spec.shell_allowed is not False
        or type(spec.attempt) is not int
        or spec.attempt != 1
        or spec.retry_of_run_id is not None
        or spec.seed_policy != "EXPLICIT_FIXED_SEEDS_NO_SELECTION"
        or spec.termination_conditions
        != ("wall_clock_timeout", "all_planned_seeds_reported")
    ):
        raise ExperimentError("reference-work policy requires a fresh native confirmatory spec")
    ledger, run_id, statistical_hash, statistical_record_hash = context
    before = _locked_scientific_execution_snapshot(registry, ledger, run_id)
    from .domains import SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID
    from .dataset_statistical_use import DatasetStatisticalUseAuthority
    from .research_state import (
        SCIENTIFIC_DATASET_ACQUISITION_ADAPTER_ID,
        SCIENTIFIC_DATASET_ACQUISITION_POLICY_ID,
        ScientificDatasetAcquisitionPlan,
        ScientificDatasetAuthority,
        ScientificDatasetSplitAuthority,
        SplitRole,
        require_scientific_dataset_acquisition_plan,
        require_scientific_dataset_authority,
        require_scientific_dataset_split_authority,
    )
    from .scientific_design import EvaluationContract, compare_fairness, require_frozen_evaluation_contract

    validate_sha256(expected_contract_artifact_sha256, "reference-work contract SHA-256")
    contract = require_frozen_evaluation_contract(
        registry, contract_artifact_sha256=expected_contract_artifact_sha256,
    )
    if type(contract) is not EvaluationContract:
        raise ExperimentError("reference-work requires the exact frozen contract type")
    timeout, wall_cap = require_generic_ml_reference_work_wall_cap(
        spec.timeout_seconds, contract.compute_budget.max_wall_seconds,
    )
    statistical_use = resolve_scientific_statistical_use_binding(
        registry, spec=spec,
        expected_contract_artifact_sha256=expected_contract_artifact_sha256,
    )
    if type(statistical_use) is not DatasetStatisticalUseAuthority:
        raise ExperimentError("reference-work policy lost its complete statistical-use owner")
    dataset = require_scientific_dataset_authority(
        registry, ledger, run_id=run_id,
        authority_artifact_hash=statistical_use.dataset_authority_artifact_hash,
    )
    split = require_scientific_dataset_split_authority(
        registry, ledger, run_id=run_id,
        split_authority_artifact_hash=statistical_use.confirmatory_split_authority_artifact_hash,
        expected_split_id=contract.dataset.confirmatory_split_id,
        expected_split_role=SplitRole.CONFIRMATORY,
    )
    if type(dataset) is not ScientificDatasetAuthority or type(split) is not ScientificDatasetSplitAuthority:
        raise ExperimentError("reference-work requires the complete Dataset and partition owners")
    acquisition = require_scientific_dataset_acquisition_plan(
        registry, ledger, run_id=run_id,
        plan_artifact_hash=dataset.acquisition_plan_artifact_hash,
        expected_dataset_id=dataset.dataset_id, expected_version=dataset.version,
    )
    if (
        type(acquisition) is not ScientificDatasetAcquisitionPlan
        or acquisition.adapter_id != SCIENTIFIC_DATASET_ACQUISITION_ADAPTER_ID
        or acquisition.policy_id != SCIENTIFIC_DATASET_ACQUISITION_POLICY_ID
        or acquisition.unit_id_field != "unit_id"
    ):
        raise ExperimentError("reference-work Dataset acquisition is not the native row profile")
    contract_record = registry.get_metadata(expected_contract_artifact_sha256)
    statistical_record = registry.get_metadata(statistical_hash)
    dataset_record = registry.get_metadata(dataset.authority_artifact_hash)
    acquisition_record = registry.get_metadata(dataset.acquisition_plan_artifact_hash)
    raw_record = registry.get_metadata(dataset.raw_data_artifact_hash)
    split_record = registry.get_metadata(split.artifact_hash)
    if (
        statistical_use.artifact_hash != statistical_hash
        or statistical_use.record_hash != statistical_record_hash
        or statistical_record.record_hash != statistical_use.record_hash
        or statistical_use.profile_id != BOUNDED_MEAN_PROFILE_ID
        or dataset.run_id != run_id
        or dataset.authority_record_hash != dataset_record.record_hash
        or dataset.acquisition_plan_record_hash != acquisition_record.record_hash
        or dataset.raw_data_record_hash != raw_record.record_hash
        or dataset.evaluation_contract_artifact_hash != contract_record.sha256
        or dataset.evaluation_contract_record_hash != contract_record.record_hash
        or dataset.dataset_id != contract.dataset.dataset_id
        or dataset.version != statistical_use.dataset_version
        or dataset.raw_data_artifact_hash != statistical_use.raw_data_artifact_hash
        or dataset.raw_data_sha256 != statistical_use.raw_data_sha256
        or raw_record.sha256 != dataset.raw_data_sha256
        or split.run_id != run_id
        or split.dataset_id != dataset.dataset_id
        or split.dataset_version != dataset.version
        or split.dataset_authority_artifact_hash != dataset_record.sha256
        or split.evaluation_contract_artifact_hash != contract_record.sha256
        or split.record_hash != split_record.record_hash
        or split.partition_sha256 != statistical_use.confirmatory_partition_sha256
        or split.member_unit_ids != statistical_use.member_unit_ids
        or split.member_unit_hashes != statistical_use.member_unit_hashes
    ):
        raise ExperimentError("reference-work Dataset and statistical-use sources are substituted")
    baselines = tuple(
        baseline for baseline in contract.baseline_registry.entries
        if baseline.status.value not in {"CONTEXT_ONLY", "INCOMPATIBLE"}
    )
    if len(baselines) != 1:
        raise ExperimentError("reference-work profile requires exactly one complete comparator")
    baseline = baselines[0]
    expected_domain_policy = {
        "schema_version": "scientific-domain-policy/v1",
        "domain": "GENERIC_ML",
        "source_format_id": SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID,
        "source_format_version": GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
        "preprocessing_fit_split_ids": [],
        "checkpoint_selection_split_id": None,
        "early_stopping": {"enabled": False, "monitor_split_id": None},
        "augmentation": {"mode": "NONE", "fit_split_ids": [], "application_split_ids": []},
        "metric_policy": {
            "schema_version": GENERIC_ML_POLICY_SCHEMA,
            "metric_id": contract.primary_metric.metric_id,
            "semantics": "EXACT_INTEGER_LABEL_MATCH",
            "aggregation": "MICRO_EXAMPLE_MEAN",
            "unit": "FRACTION",
            "direction": "HIGHER_IS_BETTER",
        },
        "generalization_scope": "WITHIN_DATASET_ONLY",
        "comparison_scope": GENERIC_ML_COMPARISON_SCOPE,
    }
    if (
        canonical_json_bytes(metadata.get("scientific_domain_policy"))
        != canonical_json_bytes(expected_domain_policy)
        or not compare_fairness(
            contract.candidate_conditions, baseline.baseline_id, baseline.conditions,
        ).equivalent
        or any(
            conditions.tuning_trials != 0
            or conditions.hyperparameter_search.strip().casefold() != "none"
            or conditions.pretrained_resources.strip().casefold() != "none"
            for conditions in (contract.candidate_conditions, baseline.conditions)
        )
        or tuple(contract.robustness_tests) != (GENERIC_ML_ROBUSTNESS_TEST_ID,)
    ):
        raise ExperimentError("reference-work policy is not exact frozen-model inference-only micro-accuracy")
    input_records = _require_scientific_execution_input_records(registry, spec)
    configuration_record = input_records[2]
    if (
        configuration_record.schema_version != "1.0"
        or configuration_record.mime_type != "application/json"
    ):
        raise ExperimentError("reference-work configuration is not the native frozen input")
    work = derive_frozen_model_reference_work(
        registry.get_bytes(raw_record.sha256),
        registry.get_bytes(configuration_record.sha256),
        member_unit_ids=split.member_unit_ids,
        member_unit_hashes=split.member_unit_hashes,
        seed_order=spec.seeds,
        contract_artifact_sha256=contract_record.sha256,
        contract_sha256=contract.sha256,
        dataset_id=contract.dataset.dataset_id,
        dataset_split_id=contract.dataset.confirmatory_split_id,
        evaluator_id=contract.candidate_conditions.evaluator,
        metric_id=contract.primary_metric.metric_id,
        metric_unit=contract.primary_metric.unit.value,
        metric_scope=contract.primary_metric.scope.value,
        candidate_condition_id=spec.experiment_id,
        baseline_condition_id=baseline.baseline_id,
    )
    for record in (contract_record, statistical_record, dataset_record, acquisition_record, raw_record, split_record, *input_records):
        if record.record_hash is None:
            raise ExperimentError("reference-work source record has no immutable identity")
    binding = ScientificReferenceWorkBinding(
        policy=policy,
        run_id=run_id,
        execution_run_id=spec.run_id,
        frozen_run_spec_sha256=spec.sha256,
        contract_record=contract_record,
        statistical_use_authority=statistical_use,
        statistical_use_record=statistical_record,
        dataset_authority=dataset,
        dataset_record=dataset_record,
        dataset_acquisition_plan_record=acquisition_record,
        raw_data_record=raw_record,
        confirmatory_split_authority=split,
        confirmatory_split_record=split_record,
        input_records=input_records,
        reference_work=work,
        timeout_seconds=timeout,
        contract_wall_cap_seconds=wall_cap,
    )
    _require_scientific_execution_snapshot_unchanged(registry, ledger, run_id, *before)
    return binding


def resolve_scientific_method_definition_binding(
    registry: ArtifactRegistry,
    *,
    spec: FrozenRunSpec,
) -> ScientificMethodDefinitionBinding | None:
    """Freshly replay a prospectively named Method definition, when present.

    Absence is the historical run-spec profile.  Once the metadata key is
    present, malformed, unsupported, missing, corrected, or cross-configuration
    bindings fail closed instead of silently falling back to the legacy
    ``UNAVAILABLE`` Method projection.
    """

    if type(registry) is not ArtifactRegistry or not isinstance(spec, FrozenRunSpec):
        raise ExperimentError(
            "scientific Method-definition replay requires exact registry and run spec"
        )
    metadata = thaw_json(spec.metadata)
    if SCIENTIFIC_METHOD_DEFINITION_BINDING_METADATA_KEY not in metadata:
        return None
    value = metadata[SCIENTIFIC_METHOD_DEFINITION_BINDING_METADATA_KEY]
    expected_keys = {
        "schema_version",
        "profile",
        "method_definition_artifact_sha256",
        "method_definition_record_hash",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != expected_keys
        or value.get("schema_version")
        != SCIENTIFIC_METHOD_DEFINITION_BINDING_SCHEMA
        or value.get("profile") != SCIENTIFIC_METHOD_DEFINITION_BINDING_PROFILE
    ):
        raise ExperimentError(
            "scientific Method-definition run-spec binding is malformed or unsupported"
        )
    digest = value.get("method_definition_artifact_sha256")
    record_hash = value.get("method_definition_record_hash")
    validate_sha256(digest, "scientific Method-definition artifact SHA-256")
    validate_sha256(record_hash, "scientific Method-definition record hash")
    try:
        registry.verify(digest, raise_on_error=True)
        record = registry.get_metadata(digest)
        raw = registry.get_bytes(digest)
        definition = safe_json_loads(raw)
    except (ArtifactError, ValidationError) as exc:
        raise ExperimentError(
            "scientific Method definition cannot be independently reopened"
        ) from exc
    if (
        record.sha256 != digest
        or str(record.record_hash) != record_hash
        or record.logical_type != "method_definition"
        or record.creator_role is not Role.HYPOTHESIS_DESIGNER
        or record.schema_version != "1.0"
        or record.mime_type != "application/json"
        or record.validation_result != "PASS"
        or record.frozen is not True
        or record.parent_artifacts != (spec.configuration_sha256,)
        or not isinstance(definition, Mapping)
        or raw != canonical_json_bytes(definition) + b"\n"
    ):
        raise ExperimentError(
            "scientific Method definition metadata, bytes, or configuration parent is substituted"
        )
    required_definition_keys = {
        "method_id",
        "name",
        "description",
        "assumptions",
        "component_ids",
    }
    assumptions = definition.get("assumptions")
    component_ids = definition.get("component_ids")
    if (
        not required_definition_keys.issubset(definition)
        or not isinstance(assumptions, list)
        or not isinstance(component_ids, list)
    ):
        raise ExperimentError(
            "scientific Method definition lacks its canonical projection fields"
        )
    try:
        return ScientificMethodDefinitionBinding(
            method_definition_artifact_sha256=record.sha256,
            method_definition_record_hash=str(record.record_hash),
            method_id=definition["method_id"],
            name=definition["name"],
            description=definition["description"],
            assumptions=tuple(assumptions),
            component_ids=tuple(component_ids),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ExperimentError(
            "scientific Method definition is malformed"
        ) from exc


@dataclass(frozen=True)
class OutputArtifact:
    path: str
    sha256: str
    size: int
    logical_type: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _relative_path(self.path, "output artifact path"))
        validate_sha256(self.sha256, "output artifact SHA-256")
        if isinstance(self.size, bool) or not isinstance(self.size, int) or not 0 <= self.size <= MAX_OUTPUT_ARTIFACT_BYTES:
            raise ExperimentError("output artifact size is invalid")
        validate_identifier(self.logical_type, "output logical type")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "logical_type": self.logical_type,
        }


@dataclass(frozen=True)
class StagedArtifact:
    """Hash-verified bytes returned by a provider-neutral compute backend."""

    descriptor: OutputArtifact
    payload: bytes = field(repr=False)
    validation_status: ValidationStatus = ValidationStatus.UNTESTED

    def __post_init__(self) -> None:
        if not isinstance(self.descriptor, OutputArtifact):
            raise ExperimentError("staged artifact descriptor must be typed")
        if not isinstance(self.payload, bytes):
            raise ExperimentError("staged artifact payload must be immutable bytes")
        if len(self.payload) != self.descriptor.size:
            raise ExperimentIntegrityError("staged artifact size differs from its manifest")
        if hashlib.sha256(self.payload).hexdigest() != self.descriptor.sha256:
            raise ExperimentIntegrityError("staged artifact digest differs from its manifest")
        if self.validation_status is not ValidationStatus.UNTESTED:
            raise ExperimentError("offline staged GPU artifacts remain UNTESTED")


@dataclass(frozen=True)
class SeedRunResult:
    seed: int
    status: SeedRunStatus
    metric: float | None
    artifact_sha256: str | None
    reason: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.seed, bool) or not isinstance(self.seed, int) or self.seed < 0:
            raise ExperimentError("seed result seed must be non-negative")
        if not isinstance(self.status, SeedRunStatus):
            try:
                object.__setattr__(self, "status", SeedRunStatus(self.status))
            except (TypeError, ValueError) as exc:
                raise ExperimentError("unknown seed result status") from exc
        if self.metric is not None:
            object.__setattr__(self, "metric", _finite_metric(self.metric, "seed metric"))
        if self.artifact_sha256 is not None:
            validate_sha256(self.artifact_sha256, "seed artifact SHA-256")
        if self.status in {SeedRunStatus.SUCCESS, SeedRunStatus.NEGATIVE, SeedRunStatus.NULL}:
            if self.metric is None or self.artifact_sha256 is None:
                raise ExperimentError("evidentiary seed result requires metric and artifact")
        if self.status in {SeedRunStatus.FAILED, SeedRunStatus.INVALID}:
            _bounded_text(self.reason, "failed seed reason")

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "status": self.status.value,
            "metric": self.metric,
            "artifact_sha256": self.artifact_sha256,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class AblationResult:
    ablation_id: str
    artifact_sha256: str
    status: str = "PASS"

    def __post_init__(self) -> None:
        validate_identifier(self.ablation_id, "ablation ID")
        validate_sha256(self.artifact_sha256, "ablation artifact SHA-256")
        if self.status not in {"PASS", "FAIL", "INVALID"}:
            raise ExperimentError("ablation status is invalid")

    def to_dict(self) -> dict[str, str]:
        return {
            "ablation_id": self.ablation_id,
            "artifact_sha256": self.artifact_sha256,
            "status": self.status,
        }


@dataclass(frozen=True)
class OutputManifest:
    run_id: str
    spec_sha256: str
    code_sha256: str
    data_sha256: str
    configuration_sha256: str
    evaluator_sha256: str
    planned_seeds: tuple[int, ...]
    seed_results: tuple[SeedRunResult, ...]
    artifacts: tuple[OutputArtifact, ...]
    ablations: tuple[AblationResult, ...] = ()
    schema_version: str = "SCIENTIST_ONE_OUTPUT_MANIFEST_V1"

    def __post_init__(self) -> None:
        validate_identifier(self.run_id, "output run ID")
        for value, label in (
            (self.spec_sha256, "spec SHA-256"),
            (self.code_sha256, "code SHA-256"),
            (self.data_sha256, "data SHA-256"),
            (self.configuration_sha256, "configuration SHA-256"),
            (self.evaluator_sha256, "evaluator SHA-256"),
        ):
            validate_sha256(value, label)
        if not isinstance(self.planned_seeds, tuple):
            object.__setattr__(self, "planned_seeds", tuple(self.planned_seeds))
        if not isinstance(self.seed_results, tuple):
            object.__setattr__(self, "seed_results", tuple(self.seed_results))
        if not isinstance(self.artifacts, tuple):
            object.__setattr__(self, "artifacts", tuple(self.artifacts))
        if not isinstance(self.ablations, tuple):
            object.__setattr__(self, "ablations", tuple(self.ablations))
        if len(self.planned_seeds) > MAX_RUN_SEEDS or len(self.seed_results) > MAX_RUN_SEEDS:
            raise ExperimentError("output seed collection exceeds safety bound")
        if len(self.artifacts) > MAX_OUTPUT_ARTIFACTS:
            raise ExperimentError("output artifact collection exceeds safety bound")
        if len(self.ablations) > MAX_ABLATIONS:
            raise ExperimentError("output ablation collection exceeds safety bound")
        if not all(isinstance(item, SeedRunResult) for item in self.seed_results):
            raise ExperimentError("seed results must be typed")
        if not all(isinstance(item, OutputArtifact) for item in self.artifacts):
            raise ExperimentError("output artifacts must be typed")
        if not all(isinstance(item, AblationResult) for item in self.ablations):
            raise ExperimentError("ablation results must be typed")
        if self.schema_version != "SCIENTIST_ONE_OUTPUT_MANIFEST_V1":
            raise ExperimentError("unsupported output manifest schema")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "spec_sha256": self.spec_sha256,
            "code_sha256": self.code_sha256,
            "data_sha256": self.data_sha256,
            "configuration_sha256": self.configuration_sha256,
            "evaluator_sha256": self.evaluator_sha256,
            "planned_seeds": list(self.planned_seeds),
            "seed_results": [item.to_dict() for item in self.seed_results],
            "artifacts": [item.to_dict() for item in self.artifacts],
            "ablations": [item.to_dict() for item in self.ablations],
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OutputManifest":
        if not isinstance(value, Mapping):
            raise ExperimentError("output manifest must be an object")
        required = {
            "schema_version",
            "run_id",
            "spec_sha256",
            "code_sha256",
            "data_sha256",
            "configuration_sha256",
            "evaluator_sha256",
            "planned_seeds",
            "seed_results",
            "artifacts",
            "ablations",
        }
        if set(value) != required:
            raise ExperimentError("output manifest schema is incomplete or unknown")
        try:
            seed_results = tuple(SeedRunResult(**dict(item)) for item in value["seed_results"])
            artifacts = tuple(OutputArtifact(**dict(item)) for item in value["artifacts"])
            ablations = tuple(AblationResult(**dict(item)) for item in value["ablations"])
            return cls(
                schema_version=value["schema_version"],
                run_id=value["run_id"],
                spec_sha256=value["spec_sha256"],
                code_sha256=value["code_sha256"],
                data_sha256=value["data_sha256"],
                configuration_sha256=value["configuration_sha256"],
                evaluator_sha256=value["evaluator_sha256"],
                planned_seeds=tuple(value["planned_seeds"]),
                seed_results=seed_results,
                artifacts=artifacts,
                ablations=ablations,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ExperimentError("malformed output manifest") from exc


@dataclass(frozen=True)
class ExecutionResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    timed_out: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.returncode, bool) or not isinstance(self.returncode, int):
            raise ExperimentError("execution returncode must be an integer")
        if not isinstance(self.stdout, bytes) or not isinstance(self.stderr, bytes):
            raise ExperimentError("execution logs must be bytes")


@dataclass(frozen=True)
class SubmissionReceipt:
    backend_id: str
    job_id: str
    idempotency_key: str
    spec_sha256: str
    state: RunState
    validation_status: ValidationStatus
    network_used: bool
    scientific_evidence: bool
    execution_plan_sha256: str | None = None
    execution_input_binding_sha256: str | None = None
    cache_hit: bool = False
    resumed_from_checkpoint_sha256: str | None = None
    network_isolation_attested: bool = False
    network_use_status: NetworkUseStatus = field(init=False)

    def __post_init__(self) -> None:
        if self.scientific_evidence:
            raise ExperimentError(
                "scientific evidence requires registry-resolved backend attestation"
            )
        if self.execution_plan_sha256 is not None:
            validate_sha256(self.execution_plan_sha256, "execution plan SHA-256")
        if self.execution_input_binding_sha256 is not None:
            validate_sha256(
                self.execution_input_binding_sha256,
                "execution input binding SHA-256",
            )
        if not isinstance(self.cache_hit, bool):
            raise ExperimentError("cache_hit must be boolean")
        object.__setattr__(
            self,
            "network_use_status",
            _derive_network_use_status(
                self.network_used,
                self.network_isolation_attested,
            ),
        )
        if self.resumed_from_checkpoint_sha256 is not None:
            validate_sha256(
                self.resumed_from_checkpoint_sha256,
                "resumed checkpoint SHA-256",
            )


@dataclass(frozen=True)
class JobStatus:
    backend_id: str
    job_id: str
    spec_sha256: str
    state: RunState
    reason: str | None
    checkpoint_sha256: str | None
    network_used: bool
    scientific_evidence: bool
    validation_status: ValidationStatus
    execution_plan_sha256: str | None = None
    execution_input_binding_sha256: str | None = None
    queue_position: int | None = None
    resumed_from_checkpoint_sha256: str | None = None
    network_isolation_attested: bool = False
    network_use_status: NetworkUseStatus = field(init=False)

    def __post_init__(self) -> None:
        if self.scientific_evidence:
            raise ExperimentError(
                "scientific evidence requires registry-resolved backend attestation"
            )
        if self.execution_plan_sha256 is not None:
            validate_sha256(self.execution_plan_sha256, "execution plan SHA-256")
        if self.execution_input_binding_sha256 is not None:
            validate_sha256(
                self.execution_input_binding_sha256,
                "execution input binding SHA-256",
            )
        object.__setattr__(
            self,
            "network_use_status",
            _derive_network_use_status(
                self.network_used,
                self.network_isolation_attested,
            ),
        )
        if (
            self.queue_position is not None
            and (
                isinstance(self.queue_position, bool)
                or not isinstance(self.queue_position, int)
                or self.queue_position < 0
            )
        ):
            raise ExperimentError("queue position must be non-negative")
        if self.resumed_from_checkpoint_sha256 is not None:
            validate_sha256(
                self.resumed_from_checkpoint_sha256,
                "resumed checkpoint SHA-256",
            )


@dataclass(frozen=True)
class CollectedRun:
    backend_id: str
    spec: FrozenRunSpec
    manifest: OutputManifest
    manifest_sha256: str
    manifest_bytes: bytes = field(repr=False)
    network_used: bool
    scientific_evidence: bool
    validation_status: ValidationStatus
    execution_plan_sha256: str | None = None
    execution_input_binding_sha256: str | None = None
    returned_artifact_sha256s: tuple[str, ...] = ()
    network_isolation_attested: bool = False
    network_use_status: NetworkUseStatus = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.manifest_bytes, bytes):
            raise ExperimentError("collected manifest bytes must be immutable bytes")
        if hashlib.sha256(self.manifest_bytes).hexdigest() != self.manifest_sha256:
            raise ExperimentIntegrityError(
                "collected manifest digest differs from its exact captured bytes"
            )
        try:
            manifest_value = safe_json_loads(
                self.manifest_bytes,
                max_bytes=MAX_OUTPUT_MANIFEST_BYTES,
            )
        except ValidationError as exc:
            raise ExperimentIntegrityError(
                "collected manifest bytes are malformed"
            ) from exc
        if (
            not isinstance(manifest_value, Mapping)
            or dict(manifest_value) != self.manifest.to_dict()
        ):
            raise ExperimentIntegrityError(
                "collected manifest bytes differ from the typed manifest"
            )
        if self.scientific_evidence:
            raise ExperimentError(
                "scientific evidence requires registry-resolved backend attestation"
            )
        if self.execution_plan_sha256 is not None:
            validate_sha256(self.execution_plan_sha256, "execution plan SHA-256")
        if self.execution_input_binding_sha256 is not None:
            validate_sha256(
                self.execution_input_binding_sha256,
                "execution input binding SHA-256",
            )
        object.__setattr__(
            self,
            "network_use_status",
            _derive_network_use_status(
                self.network_used,
                self.network_isolation_attested,
            ),
        )
        if not isinstance(self.returned_artifact_sha256s, tuple):
            object.__setattr__(
                self,
                "returned_artifact_sha256s",
                tuple(self.returned_artifact_sha256s),
            )
        if len(self.returned_artifact_sha256s) > MAX_OUTPUT_ARTIFACTS:
            raise ExperimentError("returned artifact collection exceeds safety bound")
        for value in self.returned_artifact_sha256s:
            validate_sha256(value, "returned artifact SHA-256")
        if len(set(self.returned_artifact_sha256s)) != len(
            self.returned_artifact_sha256s
        ):
            raise ExperimentError("returned artifact SHA-256 values must be unique")


@dataclass(frozen=True)
class ReproductionComparison:
    status: ReproductionStatus
    maximum_absolute_difference: float | None
    tolerance: float
    reason: str
    compared_seeds: tuple[int, ...]


@dataclass(frozen=True)
class GPUCloudCapabilities:
    cuda: bool
    single_gpu: bool
    multi_gpu: bool
    scheduled_execution: bool
    slurm: bool
    checkpoints: bool
    preemption: bool
    queues: bool
    artifact_return: bool
    validation_status: ValidationStatus = ValidationStatus.UNTESTED

    def __post_init__(self) -> None:
        for name in (
            "cuda",
            "single_gpu",
            "multi_gpu",
            "scheduled_execution",
            "slurm",
            "checkpoints",
            "preemption",
            "queues",
            "artifact_return",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ExperimentError(f"GPU capability {name} must be boolean")
        if not self.cuda or not self.single_gpu:
            raise ExperimentError("GPU_CLOUD must support CUDA single-GPU execution")
        if self.preemption and not self.checkpoints:
            raise ExperimentError("GPU preemption requires checkpoints")
        if self.slurm and (not self.scheduled_execution or not self.queues):
            raise ExperimentError("SLURM support requires scheduling and queues")
        if self.validation_status is not ValidationStatus.UNTESTED:
            raise ExperimentError("offline GPU_CLOUD capabilities remain UNTESTED")

    def to_dict(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in (
                "cuda",
                "single_gpu",
                "multi_gpu",
                "scheduled_execution",
                "slurm",
                "checkpoints",
                "preemption",
                "queues",
                "artifact_return",
            )
        } | {"validation_status": self.validation_status.value}


@runtime_checkable
class ComputeBackend(Protocol):
    """Capability-oriented backend interface shared by local and remote compute."""

    @property
    def backend_id(self) -> str: ...

    @property
    def validation_status(self) -> ValidationStatus: ...

    @property
    def network_used(self) -> bool: ...

    @property
    def network_use_status(self) -> NetworkUseStatus: ...

    @property
    def scientific_evidence(self) -> bool: ...

    def submit(self, spec: FrozenRunSpec, *, idempotency_key: str) -> SubmissionReceipt: ...

    def reconcile(self, job_id: str) -> JobStatus: ...

    def cancel(self, job_id: str) -> JobStatus: ...

    def collect(self, job_id: str) -> CollectedRun: ...


@runtime_checkable
class GPUCloudBackend(ComputeBackend, Protocol):
    """Provider-neutral remote GPU contract; no vendor is assumed."""

    @property
    def provider_name(self) -> str: ...

    @property
    def capabilities(self) -> GPUCloudCapabilities: ...

    def preemption_checkpoint(self, job_id: str) -> str | None: ...

    def queue_position(self, job_id: str) -> int | None: ...

    def returned_artifacts(self, job_id: str) -> tuple[str, ...]: ...

    def staged_artifacts(self, job_id: str) -> tuple[StagedArtifact, ...]: ...

    def requeue_from_checkpoint(
        self,
        job_id: str,
        *,
        checkpoint_token: str,
    ) -> JobStatus: ...

    def submit_planned(
        self,
        local_spec: FrozenRunSpec,
        cloud_spec: FrozenRunSpec,
        decision: EscalationDecision,
        *,
        idempotency_key: str,
    ) -> SubmissionReceipt: ...


@dataclass
class _LocalJob:
    spec: FrozenRunSpec
    idempotency_key: str
    job_id: str
    directory: Path
    state: RunState = RunState.SUBMITTED
    reason: str | None = None
    checkpoint_sha256: str | None = None
    manifest: OutputManifest | None = None
    manifest_sha256: str | None = None
    manifest_bytes: bytes | None = field(default=None, repr=False)
    artifact_hashes: tuple[tuple[str, str], ...] = ()
    execution_plan: AdaptiveExecutionPlan | None = None
    resumed_from_checkpoint_sha256: str | None = None
    execution_count: int = 0
    checkpoint_plan_bound: bool = False
    isolation_launch_evidence_sha256s: tuple[str, ...] = ()
    execution_mode: LocalMacExecutionMode = LocalMacExecutionMode.BOUND_BUILTIN
    execution_input_binding_sha256: str | None = None
    staged_input_names: Mapping[str, str] = field(default_factory=dict)
    terminal_invocation_count: int = 0
    terminal_popen_launch_count: int = 0
    terminal_result: ExecutionResult | None = None
    terminal_log_complete: bool = False
    terminal_stdout_status: str = "UNAVAILABLE"
    terminal_stderr_status: str = "UNAVAILABLE"
    terminal_observation: LocalTerminalObservation | None = None
    terminal_finished: threading.Event = field(default_factory=threading.Event, repr=False)
    terminal_directory_identity: tuple[int, int] | None = None


@dataclass
class _ActiveLocalProcess:
    """Backend-owned identity for one isolated local process group."""

    process: subprocess.Popen[bytes]
    process_group_id: int
    session_id: int
    termination_lock: threading.Lock = field(default_factory=threading.Lock)


ExecutionRunner = Callable[[FrozenRunSpec, Path, Mapping[str, str]], ExecutionResult]


def _stable_file_sha256(
    path: Path,
    label: str,
    *,
    reject_hardlinks: bool = False,
) -> str:
    """Hash one non-symlink regular file and reject a concurrent replacement."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ExperimentError(f"{label} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or (
            reject_hardlinks and before.st_nlink != 1
        ):
            raise ExperimentError(f"{label} must be a trusted regular file")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ExperimentIntegrityError(f"{label} changed while it was hashed")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _seatbelt_literal(path: Path) -> str:
    value = str(path)
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise ExperimentError("Seatbelt path contains a forbidden control character")
    return value.replace("\\", "\\\\").replace('"', '\\"')


class LocalMacBackend:
    """Synchronous, bounded, local CPU/MPS-host experiment executor.

    ``REQUIRED`` isolation is deliberately opt-in. It permits only this class's
    built-in launcher and uses Apple's Seatbelt executable for network denial,
    job-only writes, and exact executable admission. Read isolation and OS
    rlimits are explicitly not claimed. Its immutable launch record hash-binds
    the intended launch for technical review; it is not proof against a
    coherent same-user path race. Scientific authority still belongs to the
    source-owned registry resolver above this backend.
    """

    backend_id = "local-mac"
    validation_status = ValidationStatus.VALIDATED_LOCAL
    network_used = False
    network_use_status = NetworkUseStatus.UNKNOWN_UNATTESTED
    # A backend-local technical launch record is not registry-resolved
    # scientific authority, and this profile does not isolate filesystem reads.
    # The public evidence and network-attestation fields therefore stay false.
    scientific_evidence = False

    def __init__(
        self,
        project_root: str | os.PathLike[str],
        *,
        allowed_executables: Iterable[str],
        execution_runner: ExecutionRunner | None = None,
        observed_available_memory_bytes: int = 2 * 1024**3,
        maximum_concurrency_cap: int = 1,
        queue_timeout_seconds: float = 30.0,
        validated_mps_artifact_sha256s: Iterable[str] = (),
        isolation_mode: LocalMacIsolationMode = LocalMacIsolationMode.DISABLED,
        execution_mode: LocalMacExecutionMode | None = None,
    ) -> None:
        self._root = canonical_root(project_root)
        allowed = tuple(allowed_executables)
        if not allowed or any(not isinstance(item, str) or not item for item in allowed):
            raise ExperimentError("an explicit executable allowlist is required")
        self._allowed_executables = allowed
        if not isinstance(isolation_mode, LocalMacIsolationMode):
            try:
                isolation_mode = LocalMacIsolationMode(isolation_mode)
            except (TypeError, ValueError) as exc:
                raise ExperimentError("unknown Local Mac isolation mode") from exc
        if execution_mode is None:
            execution_mode = LocalMacExecutionMode.BOUND_BUILTIN
        elif not isinstance(execution_mode, LocalMacExecutionMode):
            try:
                execution_mode = LocalMacExecutionMode(execution_mode)
            except (TypeError, ValueError) as exc:
                raise ExperimentError("unknown Local Mac execution mode") from exc
        if (
            execution_mode is LocalMacExecutionMode.BOUND_BUILTIN
            and execution_runner is not None
        ):
            raise ExperimentError(
                "injected execution runners require explicit diagnostic mode"
            )
        if (
            execution_mode is LocalMacExecutionMode.INJECTED_DIAGNOSTIC
            and execution_runner is None
        ):
            raise ExperimentError(
                "diagnostic mode requires an explicit injected execution runner"
            )
        if isolation_mode is LocalMacIsolationMode.REQUIRED and execution_runner is not None:
            raise ExperimentError(
                "REQUIRED Local Mac isolation forbids injected execution runners"
            )
        if (
            isolation_mode is LocalMacIsolationMode.REQUIRED
            and execution_mode is not LocalMacExecutionMode.BOUND_BUILTIN
        ):
            raise ExperimentError(
                "REQUIRED Local Mac isolation requires bound built-in execution"
            )
        self._isolation_mode = isolation_mode
        self._execution_mode = execution_mode
        self._execution_runner = execution_runner or self._run_subprocess
        if execution_mode is LocalMacExecutionMode.BOUND_BUILTIN:
            self._require_exact_builtin_runner()
        if isolation_mode is LocalMacIsolationMode.REQUIRED:
            self._require_isolation_available()
        if (
            isinstance(observed_available_memory_bytes, bool)
            or not isinstance(observed_available_memory_bytes, int)
            or not 1 <= observed_available_memory_bytes <= MAX_COMPUTE_MEMORY_BYTES
        ):
            raise ExperimentError("observed available memory is invalid")
        if (
            isinstance(maximum_concurrency_cap, bool)
            or not isinstance(maximum_concurrency_cap, int)
            or not 1 <= maximum_concurrency_cap <= MAX_COMPUTE_CONCURRENCY
        ):
            raise ExperimentError("local concurrency cap is invalid")
        queue_timeout = _finite_metric(queue_timeout_seconds, "queue timeout")
        if queue_timeout <= 0 or queue_timeout > 3600:
            raise ExperimentError("queue timeout is outside its bounded range")
        self._observed_available_memory_bytes = observed_available_memory_bytes
        self._maximum_concurrency_cap = maximum_concurrency_cap
        self._queue_timeout_seconds = queue_timeout
        if isinstance(validated_mps_artifact_sha256s, (str, bytes)):
            raise ExperimentError("validated MPS artifacts must be a digest collection")
        validated_mps = tuple(validated_mps_artifact_sha256s)
        for artifact_sha256 in validated_mps:
            validate_sha256(artifact_sha256, "validated MPS artifact SHA-256")
        self._validated_mps_artifact_sha256s = frozenset(validated_mps)
        self._execution_slots = threading.BoundedSemaphore(maximum_concurrency_cap)
        self._jobs: dict[str, _LocalJob] = {}
        self._idempotency: dict[str, tuple[str, str]] = {}
        self._spec_jobs: dict[str, str] = {}
        self._run_specs: dict[str, str] = {}
        self._active_processes: dict[str, _ActiveLocalProcess] = {}
        self._lock = threading.RLock()
        secure_directory(self._root, ".scientist-one-build", create=True)
        secure_directory(self._root, ".scientist-one-build/experiments", create=True)
        secure_directory(self._root, ".scientist-one-build/experiments/local-mac", create=True)

    @property
    def isolation_mode(self) -> LocalMacIsolationMode:
        return self._isolation_mode

    @property
    def execution_mode(self) -> LocalMacExecutionMode:
        return self._execution_mode

    @staticmethod
    def isolation_available() -> bool:
        """Return whether the reviewed macOS launcher dependencies are present."""

        sandbox = Path(LOCAL_MAC_SANDBOX_EXECUTABLE)
        return (
            sys.platform == "darwin"
            and sandbox.is_file()
            and os.access(sandbox, os.X_OK)
        )

    @classmethod
    def _require_isolation_available(cls) -> None:
        if not cls.isolation_available():
            raise ExperimentError(
                "REQUIRED Local Mac isolation is unavailable on this host"
            )

    def _require_exact_builtin_runner(self) -> None:
        runner = self._execution_runner
        if (
            type(self) is not LocalMacBackend
            or getattr(runner, "__self__", None) is not self
            or getattr(runner, "__func__", None) is not LocalMacBackend._run_subprocess
        ):
            raise ExperimentIntegrityError(
                "bound local execution requires the exact built-in LocalMacBackend runner"
            )

    def _terminal_profile(self, spec: FrozenRunSpec) -> bool:
        """Admit only the closed, operational, non-resumable capture profile."""

        if LOCAL_TERMINAL_CAPTURE_METADATA_KEY not in spec.metadata:
            return False
        validate_terminal_capture_limits()
        if canonical_json_bytes(
            thaw_json(spec.metadata[LOCAL_TERMINAL_CAPTURE_METADATA_KEY])
        ) != canonical_json_bytes(dict(LOCAL_TERMINAL_CAPTURE_PROFILE)):
            raise ExperimentError("unsupported local terminal capture marker")
        if (
            spec.evidence_class is not EvidenceClass.NON_EVIDENTIARY
            or spec.phase is not ExperimentPhase.EXPLORATORY
            or spec.compute_profile.mode is not ComputeMode.LOCAL_MAC
            or spec.compute_profile.accelerator is not AcceleratorKind.CPU
            or spec.checkpoint_policy is not CheckpointPolicy.DISABLED
            or self._execution_mode is not LocalMacExecutionMode.BOUND_BUILTIN
            or self._isolation_mode is not LocalMacIsolationMode.DISABLED
            or max(spec.maximum_stdout_bytes, spec.maximum_stderr_bytes)
            > LOCAL_TERMINAL_MAX_LOG_BYTES
            or any(
                "resume" in name.lower() or "checkpoint" in name.lower()
                for name in spec.metadata
            )
            or len(canonical_json_bytes(spec.to_dict())) + 1
            > LOCAL_TERMINAL_MAX_FILE_BYTES
        ):
            raise ExperimentError("unsupported local terminal capture execution scope")
        self._require_exact_builtin_runner()
        return True

    @staticmethod
    def _terminal_identity(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    def _terminal_directory(self, job: _LocalJob) -> tuple[int, int]:
        descriptor = open_confined_directory_fd(
            self._root,
            job.directory.relative_to(self._root),
            create=False,
        )
        try:
            metadata = os.fstat(descriptor)
            identity = (metadata.st_dev, metadata.st_ino)
            if job.terminal_directory_identity not in (None, identity):
                raise ExperimentIntegrityError("terminal job directory was substituted")
            return identity
        finally:
            os.close(descriptor)

    def _terminal_file(
        self,
        job: _LocalJob,
        role: str,
        path: str,
        *,
        remaining: int,
    ) -> LocalTerminalFile:
        """Observe a confined entry using held parents; never open unsafe kinds.

        Both the held inode and its named directory entry must remain exact.
        This is bounded local race detection, not anti-same-principal attestation.
        """

        if (
            type(path) is not str
            or not 1 <= len(path) <= 1024
            or path.startswith("/")
            or "\\" in path
            or "\x00" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            return LocalTerminalFile(role, path, "UNSAFE", None, None)
        directory_fd = open_confined_directory_fd(
            self._root,
            job.directory.relative_to(self._root),
            create=False,
        )
        descriptors = [directory_fd]
        parents: list[tuple[int, str, int]] = []
        try:
            metadata = os.fstat(directory_fd)
            if (metadata.st_dev, metadata.st_ino) != job.terminal_directory_identity:
                raise ExperimentIntegrityError(
                    "terminal job directory identity changed"
                )
            for part in path.split("/")[:-1]:
                try:
                    child = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=directory_fd,
                    )
                except FileNotFoundError:
                    return LocalTerminalFile(role, path, "MISSING", None, None)
                except PermissionError:
                    return LocalTerminalFile(role, path, "UNAVAILABLE", None, None)
                except OSError as exc:
                    status = (
                        "UNSAFE"
                        if exc.errno in {errno.ELOOP, errno.ENOTDIR}
                        else "ERROR"
                    )
                    return LocalTerminalFile(role, path, status, None, None)
                parents.append((directory_fd, part, child))
                descriptors.append(child)
                directory_fd = child
            name = path.split("/")[-1]
            try:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                return LocalTerminalFile(role, path, "MISSING", None, None)
            except PermissionError:
                return LocalTerminalFile(role, path, "UNAVAILABLE", None, None)
            except OSError:
                return LocalTerminalFile(role, path, "ERROR", None, None)
            identity = self._terminal_identity(metadata)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                return LocalTerminalFile(role, path, "UNSAFE", identity, None)
            if metadata.st_size > min(LOCAL_TERMINAL_MAX_FILE_BYTES, remaining):
                return LocalTerminalFile(role, path, "OVER_LIMIT", identity, None)
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=directory_fd,
                )
            except PermissionError:
                return LocalTerminalFile(role, path, "UNAVAILABLE", identity, None)
            except FileNotFoundError as exc:
                raise ExperimentIntegrityError(
                    "terminal entry disappeared during capture"
                ) from exc
            except OSError:
                return LocalTerminalFile(role, path, "ERROR", identity, None)
            try:
                if self._terminal_identity(os.fstat(descriptor)) != identity:
                    raise ExperimentIntegrityError(
                        "terminal entry changed before capture"
                    )
                capture_status = "CAPTURED"
                try:
                    payload = self._read_held_descriptor(
                        descriptor,
                        maximum_bytes=min(LOCAL_TERMINAL_MAX_FILE_BYTES, remaining),
                    )
                except OSError as exc:
                    # Ordinary read unavailability is a partial observation.
                    # Still prove the held/named identities below; integrity
                    # errors and any unprovable post-read identity stay unresolved.
                    payload = None
                    capture_status = (
                        "UNAVAILABLE" if isinstance(exc, PermissionError) else "ERROR"
                    )
                if (
                    self._terminal_identity(os.fstat(descriptor)) != identity
                    or self._terminal_identity(
                        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    )
                    != identity
                ):
                    raise ExperimentIntegrityError(
                        "terminal entry changed during capture"
                    )
            finally:
                os.close(descriptor)
            for parent, part, child in parents:
                named = os.stat(part, dir_fd=parent, follow_symlinks=False)
                held = os.fstat(child)
                if (named.st_dev, named.st_ino, named.st_mode) != (
                    held.st_dev,
                    held.st_ino,
                    held.st_mode,
                ):
                    raise ExperimentIntegrityError("terminal parent was substituted")
            self._terminal_directory(job)
            return LocalTerminalFile(role, path, capture_status, identity, payload)
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def _terminal_sources(self, job: _LocalJob) -> tuple[str, ...]:
        return (
            "frozen-run-spec.json",
            "execution-plan.json",
            "execution-mode.json",
            "execution-input-binding.json",
            *(job.staged_input_names[kind] for kind in LOCAL_MAC_EXECUTION_INPUT_KINDS),
        )

    def _terminal_dispatch_intent(self, job: _LocalJob) -> dict[str, Any]:
        return {
            "schema_version": "SCIENTIST_ONE_LOCAL_TERMINAL_DISPATCH_INTENT_V1",
            "spec_sha256": job.spec.sha256,
            "job_id": job.job_id,
            "invocation_index": 1,
            "scientific_evidence": False,
        }

    def _require_terminal_source_bytes(
        self, job: _LocalJob, files: list[LocalTerminalFile]
    ) -> None:
        assert job.execution_plan is not None
        expected = {
            "frozen-run-spec.json": hashlib.sha256(
                canonical_json_bytes(job.spec.to_dict()) + b"\n"
            ).hexdigest(),
            "execution-plan.json": hashlib.sha256(
                canonical_json_bytes(job.execution_plan.to_dict()) + b"\n"
            ).hexdigest(),
            "execution-mode.json": hashlib.sha256(
                canonical_json_bytes(self._execution_mode_payload()) + b"\n"
            ).hexdigest(),
            "execution-input-binding.json": job.execution_input_binding_sha256,
            **{
                job.staged_input_names[kind]: getattr(job.spec, f"{kind}_sha256")
                for kind in LOCAL_MAC_EXECUTION_INPUT_KINDS
            },
        }
        if job.terminal_invocation_count:
            expected["terminal-dispatch-intent.json"] = hashlib.sha256(
                canonical_json_bytes(self._terminal_dispatch_intent(job)) + b"\n"
            ).hexdigest()
        sources = {item.path: item for item in files if item.role == "source"}
        if set(sources) != set(expected) or any(
            sources[path].sha256 != digest for path, digest in expected.items()
        ):
            raise ExperimentIntegrityError(
                "terminal source bytes differ from admitted execution"
            )

    def _terminal_snapshot(
        self, job: _LocalJob
    ) -> tuple[tuple[LocalTerminalFile, ...], str]:
        files: list[LocalTerminalFile] = []
        remaining = LOCAL_TERMINAL_MAX_TOTAL_BYTES

        def add(role: str, path: str) -> LocalTerminalFile:
            nonlocal remaining
            item = self._terminal_file(job, role, path, remaining=remaining)
            files.append(item)
            remaining -= len(item.payload or b"")
            return item

        for path in self._terminal_sources(job):
            if add("source", path).status != "CAPTURED":
                raise ExperimentIntegrityError(
                    "terminal execution source is unavailable"
                )
        if job.terminal_invocation_count:
            if add("source", "terminal-dispatch-intent.json").status != "CAPTURED":
                raise ExperimentIntegrityError(
                    "terminal dispatch intent is unavailable"
                )
        elif (
            self._terminal_file(
                job,
                "source",
                "terminal-dispatch-intent.json",
                remaining=LOCAL_TERMINAL_MAX_FILE_BYTES,
            ).status
            != "MISSING"
        ):
            raise ExperimentIntegrityError(
                "unresolved dispatch intent cannot certify zero invocations"
            )
        self._require_terminal_source_bytes(job, files)
        add("log", "stdout.log")
        add("log", "stderr.log")
        manifest = add("manifest", "output-manifest.json")
        inventory = "UNRESOLVED_MANIFEST"
        if manifest.payload is not None:
            try:
                value = safe_json_loads(
                    manifest.payload, max_bytes=LOCAL_TERMINAL_MAX_FILE_BYTES
                )
                artifacts = (
                    value.get("artifacts") if isinstance(value, Mapping) else None
                )
                if (
                    type(artifacts) is list
                    and len(artifacts) <= LOCAL_TERMINAL_MAX_OUTPUTS
                ):
                    inventory = "MANIFEST_DECLARED_PATHS"
                    seen = {item.path for item in files}
                    for artifact in artifacts:
                        path = (
                            artifact.get("path")
                            if isinstance(artifact, Mapping)
                            else None
                        )
                        if (
                            type(path) is not str
                            or not 1 <= len(path) <= 1024
                            or path in seen
                        ):
                            inventory = "UNRESOLVED_MANIFEST"
                            continue
                        try:
                            path.encode("utf-8")
                        except UnicodeEncodeError:
                            # The exact escaped path remains in raw manifest
                            # bytes. Do not invent a sanitized filesystem name
                            # or an unencodable canonical DTO string.
                            inventory = "UNRESOLVED_MANIFEST"
                            continue
                        seen.add(path)
                        add("output", path)
            except ValidationError:
                inventory = "UNRESOLVED_MANIFEST"
        return tuple(files), inventory

    def _replay_terminal_files(
        self, job: _LocalJob, observation: LocalTerminalObservation
    ) -> None:
        if self._terminal_directory(job) != observation.directory_identity:
            raise ExperimentIntegrityError(
                "terminal directory differs from recorded identity"
            )
        files, inventory = self._terminal_snapshot(job)
        if (
            files != observation.files
            or inventory != observation.delivery_inventory_status
        ):
            raise ExperimentIntegrityError("terminal source or delivered bytes changed")

    def _finish_terminal(
        self, job: _LocalJob, result: ExecutionResult | None
    ) -> SubmissionReceipt:
        """Commit the terminal observation last, or leave an unresolved prefix."""

        try:
            with self._lock:
                if job.terminal_popen_launch_count and job.terminal_result is None:
                    raise ExperimentIntegrityError(
                        "launched process termination remains unresolved"
                    )
                if result is not None:
                    job.terminal_result = result
                    for name, payload in (
                        ("stdout.log", result.stdout),
                        ("stderr.log", result.stderr),
                    ):
                        atomic_write_bytes(
                            self._root, job.directory / name, payload, immutable=True
                        )
                files, inventory = self._terminal_snapshot(job)
                if (
                    result is not None
                    and job.state is not RunState.CANCELLED
                    and job.reason != "EXECUTION_EXCEPTION"
                ):
                    if not job.terminal_log_complete:
                        job.state, job.reason = RunState.FAILED, "LOG_CAPTURE_EXCEPTION"
                    elif result.timed_out:
                        job.state, job.reason = RunState.FAILED, "WALL_CLOCK_TIMEOUT"
                    elif result.returncode != 0:
                        job.state, job.reason = (
                            RunState.FAILED,
                            f"PROCESS_EXIT:{result.returncode}",
                        )
                    else:
                        try:
                            if inventory != "MANIFEST_DECLARED_PATHS" or any(
                                item.status != "CAPTURED" for item in files
                            ):
                                raise ExperimentIntegrityError(
                                    "terminal output capture is incomplete"
                                )
                            self._capture_and_validate_manifest(job, first_capture=True)
                            job.state, job.reason = (
                                RunState.SUCCEEDED,
                                "VALIDATED_OUTPUTS_OPERATIONAL_ONLY",
                            )
                        except (
                            ValidationError,
                            ExperimentIntegrityError,
                            PathSecurityError,
                        ):
                            job.state, job.reason = (
                                RunState.INVALID_OUTPUT,
                                "OUTPUT_INVALID",
                            )
                if job.state is not RunState.SUCCEEDED:
                    job.manifest = None
                    job.manifest_sha256 = None
                    job.manifest_bytes = None
                    job.artifact_hashes = ()
                assert job.execution_plan is not None
                assert job.execution_input_binding_sha256 is not None
                assert job.terminal_directory_identity is not None
                observation = LocalTerminalObservation(
                    job_id=job.job_id,
                    submission_idempotency_key=job.idempotency_key,
                    spec_sha256=job.spec.sha256,
                    execution_plan_sha256=job.execution_plan.sha256,
                    execution_input_binding_sha256=job.execution_input_binding_sha256,
                    directory_identity=job.terminal_directory_identity,
                    state=job.state.value,
                    reason=job.reason or "TERMINAL_OPERATIONAL_ONLY",
                    invocation_count=job.terminal_invocation_count,
                    proven_popen_launch_count=job.terminal_popen_launch_count,
                    launch_observation=(
                        "NOT_INVOKED"
                        if job.terminal_invocation_count == 0
                        else "POPEN_RETURNED"
                        if job.terminal_popen_launch_count == 1
                        else "UNKNOWN_AFTER_INVOCATION"
                    ),
                    returncode=result.returncode if result is not None else None,
                    timed_out=result.timed_out if result is not None else None,
                    stdout_truncated=(
                        result.stdout_truncated
                        if result is not None
                        and (
                            result.stdout_truncated
                            or job.terminal_stdout_status == "COMPLETE"
                        )
                        else None
                    ),
                    stderr_truncated=(
                        result.stderr_truncated
                        if result is not None
                        and (
                            result.stderr_truncated
                            or job.terminal_stderr_status == "COMPLETE"
                        )
                        else None
                    ),
                    stdout_capture_status=job.terminal_stdout_status,
                    stderr_capture_status=job.terminal_stderr_status,
                    log_capture_complete=job.terminal_log_complete,
                    delivery_inventory_status=inventory,
                    accepted_manifest_sha256=job.manifest_sha256,
                    files=files,
                )
                self._replay_terminal_files(job, observation)
                atomic_write_bytes(
                    self._root,
                    job.directory / LOCAL_TERMINAL_OBSERVATION_FILENAME,
                    observation.payload,
                    immutable=True,
                )
                job.terminal_observation = observation
                self.collect_terminal_observation(job.job_id)
                return self._receipt(job)
        finally:
            job.terminal_finished.set()

    def collect_terminal_observation(self, job_id: str) -> LocalTerminalObservation:
        """Replay immutable native operational bytes; never infer successful work."""

        with self._lock:
            job = self._job(job_id)
            if not self._terminal_profile(job.spec):
                raise ExperimentError("job did not opt into terminal capture")
            payload = read_confined_bytes(
                self._root,
                job.directory / LOCAL_TERMINAL_OBSERVATION_FILENAME,
                reject_hardlinks=True,
                max_bytes=LOCAL_TERMINAL_MAX_JSON_BYTES,
                missing_ok=True,
            )
            if payload is None or job.terminal_observation is None:
                raise ExperimentIntegrityError(
                    "terminal capture is unresolved; dispatch is forbidden"
                )
            observation = LocalTerminalObservation.from_bytes(payload)
            if observation != job.terminal_observation:
                raise ExperimentIntegrityError("terminal record was substituted")
            self._replay_terminal_files(job, observation)
            return observation

    def recover_terminal_observation(
        self,
        spec: FrozenRunSpec,
        *,
        idempotency_key: str,
    ) -> LocalTerminalObservation:
        """Rehydrate exact terminal runtime bytes without invoking a child."""

        if not isinstance(spec, FrozenRunSpec) or not self._terminal_profile(spec):
            raise ExperimentError(
                "recovery requires the local terminal capture profile"
            )
        validate_identifier(idempotency_key, "idempotency key")
        self._validate_local_profile(spec)
        validate_command(
            spec.argv,
            allowed_executables=self._allowed_executables,
            root=self._root,
            allowed_python_modules=(),
        )
        with self._lock:
            previous = self._idempotency.get(idempotency_key)
            if previous is not None and previous[0] != spec.sha256:
                raise SubmissionConflictError(
                    "idempotency key names a different run spec"
                )
            job_id = f"local-{spec.sha256[:20]}{self._local_job_suffix()}"
            if job_id in self._jobs:
                observation = self.collect_terminal_observation(job_id)
                self._idempotency[idempotency_key] = (spec.sha256, job_id)
                return observation
            if self._run_specs.get(spec.run_id, spec.sha256) != spec.sha256:
                raise SubmissionConflictError("run ID names a different frozen spec")
            directory = secure_directory(
                self._root,
                f".scientist-one-build/experiments/local-mac/{job_id}",
                create=False,
            )
            payload = read_confined_bytes(
                self._root,
                directory / LOCAL_TERMINAL_OBSERVATION_FILENAME,
                reject_hardlinks=True,
                max_bytes=LOCAL_TERMINAL_MAX_JSON_BYTES,
                missing_ok=True,
            )
            if payload is None:
                raise ExperimentIntegrityError(
                    "terminal capture is unresolved; dispatch is forbidden"
                )
            observation = LocalTerminalObservation.from_bytes(payload)
            if observation.job_id != job_id or observation.spec_sha256 != spec.sha256:
                raise ExperimentIntegrityError("terminal frozen identity mismatch")
            by_path = {item.path: item for item in observation.files}
            for path, expected in (
                ("frozen-run-spec.json", canonical_json_bytes(spec.to_dict()) + b"\n"),
                (
                    "execution-mode.json",
                    canonical_json_bytes(self._execution_mode_payload()) + b"\n",
                ),
            ):
                if path not in by_path or by_path[path].payload != expected:
                    raise ExperimentIntegrityError(
                        "terminal spec or execution mode differs"
                    )
            if (
                "execution-plan.json" not in by_path
                or by_path["execution-plan.json"].payload is None
            ):
                raise ExperimentIntegrityError("terminal execution plan is absent")
            plan = AdaptiveExecutionPlan.from_mapping(
                safe_json_loads(by_path["execution-plan.json"].payload)
            )
            _validate_adaptive_plan_binding(
                plan,
                spec.compute_profile,
                spec.resource_estimate,
                pending_tasks=len(spec.seeds),
                bytes_per_sample=spec.bytes_per_sample,
                worker_overhead_bytes=spec.worker_overhead_bytes,
            )
            names, binding = self._load_staged_execution_inputs(spec, directory)
            if (
                set(names) != set(LOCAL_MAC_EXECUTION_INPUT_KINDS)
                or binding != observation.execution_input_binding_sha256
                or plan.sha256 != observation.execution_plan_sha256
            ):
                raise ExperimentIntegrityError("terminal plan or input binding differs")
            job = _LocalJob(
                spec=spec,
                idempotency_key=idempotency_key,
                job_id=job_id,
                directory=directory,
                state=RunState(observation.state),
                reason=observation.reason,
                execution_plan=plan,
                execution_input_binding_sha256=binding,
                staged_input_names=names,
                execution_count=observation.invocation_count,
                terminal_invocation_count=observation.invocation_count,
                terminal_popen_launch_count=observation.proven_popen_launch_count,
                terminal_directory_identity=observation.directory_identity,
                terminal_observation=observation,
                terminal_log_complete=observation.log_capture_complete,
                terminal_stdout_status=observation.stdout_capture_status,
                terminal_stderr_status=observation.stderr_capture_status,
            )
            self._replay_terminal_files(job, observation)
            if job.state is RunState.SUCCEEDED:
                self._capture_and_validate_manifest(job, first_capture=True)
                if job.manifest_sha256 != observation.accepted_manifest_sha256:
                    raise ExperimentIntegrityError("accepted terminal manifest differs")
            self._replay_terminal_files(job, observation)
            job.terminal_finished.set()
            self._jobs[job_id] = job
            self._idempotency[idempotency_key] = (spec.sha256, job_id)
            self._spec_jobs[spec.sha256] = job_id
            self._run_specs[spec.run_id] = spec.sha256
            return self.collect_terminal_observation(job_id)

    def _execute_terminal_job(self, job: _LocalJob) -> SubmissionReceipt:
        acquired = self._execution_slots.acquire(timeout=self._queue_timeout_seconds)
        if not acquired:
            with self._lock:
                if job.terminal_observation is not None:
                    self.collect_terminal_observation(job.job_id)
                    return self._receipt(job)
                if job.state is not RunState.CANCELLED:
                    job.state, job.reason = RunState.FAILED, "LOCAL_QUEUE_TIMEOUT"
                return self._finish_terminal(job, None)
        try:
            with self._lock:
                if job.state is RunState.CANCELLED:
                    if job.terminal_observation is None:
                        return self._finish_terminal(job, None)
                    self.collect_terminal_observation(job.job_id)
                    return self._receipt(job)
                job.state = RunState.RUNNING
            try:
                environment = self._scrubbed_environment(job.spec, job.directory)
                self._require_exact_builtin_runner()
                with self._lock:
                    if job.state is RunState.CANCELLED:
                        if job.terminal_observation is None:
                            return self._finish_terminal(job, None)
                        self.collect_terminal_observation(job.job_id)
                        return self._receipt(job)
                    atomic_write_json(
                        self._root,
                        job.directory / "terminal-dispatch-intent.json",
                        self._terminal_dispatch_intent(job),
                        immutable=True,
                    )
                    # An invocation is not a process launch. Only successful
                    # Popen return in the exact builtin launcher counts a launch.
                    job.terminal_invocation_count += 1
                    job.execution_count += 1
                result = self._execution_runner(job.spec, job.directory, environment)
                if not isinstance(result, ExecutionResult):
                    raise ExperimentIntegrityError(
                        "builtin execution result is invalid"
                    )
            except BaseException:
                with self._lock:
                    if job.state is not RunState.CANCELLED:
                        job.state, job.reason = RunState.FAILED, "EXECUTION_EXCEPTION"
                    self._finish_terminal(job, job.terminal_result)
                raise
            return self._finish_terminal(job, result)
        finally:
            self._execution_slots.release()

    def _validate_local_profile(self, spec: FrozenRunSpec) -> None:
        if spec.compute_profile.mode is not ComputeMode.LOCAL_MAC:
            raise ExperimentError("LocalMacBackend requires a LOCAL_MAC compute profile")
        if spec.compute_profile.accelerator is AcceleratorKind.MPS:
            validation_sha256 = spec.compute_profile.validation_artifact_sha256
            if validation_sha256 not in self._validated_mps_artifact_sha256s:
                raise ExperimentError(
                    "MPS profile validation artifact is not trusted by this backend"
                )

    @staticmethod
    def _job_is_scientific_evidence(job: _LocalJob) -> bool:
        # There is deliberately no attestation input or mutation seam here.
        # Until a backend-owned OS isolation implementation can produce and
        # verify a content-bound attestation, LOCAL_MAC output is never
        # scientific evidence, even when the caller declares it eligible.
        return False

    @staticmethod
    def _job_validation_status(job: _LocalJob) -> ValidationStatus:
        if job.execution_mode is LocalMacExecutionMode.INJECTED_DIAGNOSTIC:
            return ValidationStatus.UNTESTED
        # A trusted artifact reference allows the MPS boundary to be exercised,
        # but this offline implementation does not claim a real MPS hardware run.
        if job.spec.compute_profile.accelerator is AcceleratorKind.MPS:
            return ValidationStatus.UNTESTED
        return ValidationStatus.VALIDATED_LOCAL

    def _receipt(self, job: _LocalJob, *, cache_hit: bool = False) -> SubmissionReceipt:
        verified_cache_hit = (
            cache_hit
            and job.state is RunState.SUCCEEDED
            and job.manifest is not None
            and job.manifest_sha256 is not None
        )
        return SubmissionReceipt(
            backend_id=self.backend_id,
            job_id=job.job_id,
            idempotency_key=job.idempotency_key,
            spec_sha256=job.spec.sha256,
            state=job.state,
            validation_status=self._job_validation_status(job),
            network_used=False,
            scientific_evidence=self._job_is_scientific_evidence(job),
            execution_plan_sha256=(
                job.execution_plan.sha256 if job.execution_plan is not None else None
            ),
            execution_input_binding_sha256=(
                job.execution_input_binding_sha256
            ),
            cache_hit=verified_cache_hit,
            resumed_from_checkpoint_sha256=job.resumed_from_checkpoint_sha256,
            network_isolation_attested=False,
        )

    def _status(self, job: _LocalJob) -> JobStatus:
        reason = job.reason
        diagnostic_reason = "INJECTED_DIAGNOSTIC_UNTESTED_UNPROMOTABLE"
        if (
            job.execution_mode is LocalMacExecutionMode.INJECTED_DIAGNOSTIC
            and diagnostic_reason not in (reason or "")
        ):
            reason = f"{reason},{diagnostic_reason}" if reason else diagnostic_reason
        return JobStatus(
            backend_id=self.backend_id,
            job_id=job.job_id,
            spec_sha256=job.spec.sha256,
            state=job.state,
            reason=reason,
            checkpoint_sha256=job.checkpoint_sha256,
            network_used=False,
            scientific_evidence=self._job_is_scientific_evidence(job),
            validation_status=self._job_validation_status(job),
            execution_plan_sha256=(
                job.execution_plan.sha256 if job.execution_plan is not None else None
            ),
            execution_input_binding_sha256=(
                job.execution_input_binding_sha256
            ),
            queue_position=0 if job.state is RunState.QUEUED else None,
            resumed_from_checkpoint_sha256=job.resumed_from_checkpoint_sha256,
            network_isolation_attested=False,
        )

    def _job(self, job_id: str) -> _LocalJob:
        validate_identifier(job_id, "job ID")
        try:
            return self._jobs[job_id]
        except KeyError as exc:
            raise ExperimentError("unknown local job") from exc

    def _environment_for_job(
        self,
        job: _LocalJob,
        *,
        resume_marker: str | None = None,
    ) -> Mapping[str, str]:
        spec = job.spec
        directory = job.directory
        if job.execution_plan is None:
            raise ExperimentIntegrityError("local execution plan is unavailable")
        environment = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "SCIENTIST_ONE_NETWORK_POLICY": "DENY",
            "SCIENTIST_ONE_RUN_ID": spec.run_id,
            "SCIENTIST_ONE_SPEC_SHA256": spec.sha256,
            "SCIENTIST_ONE_JOB_DIR": str(directory),
            "SCIENTIST_ONE_OUTPUT_MANIFEST": str(directory / "output-manifest.json"),
            "SCIENTIST_ONE_CHECKPOINT": str(directory / "checkpoint.json"),
            "SCIENTIST_ONE_EXECUTION_INPUT_BINDING_SHA256": (
                job.execution_input_binding_sha256 or "UNBOUND_NON_EVIDENTIARY"
            ),
        }
        plan = job.execution_plan
        marker = (
            job.resumed_from_checkpoint_sha256
            if resume_marker is None
            else resume_marker
        )
        environment.update(
            {
                "SCIENTIST_ONE_COMPUTE_MODE": spec.compute_profile.mode.value,
                "SCIENTIST_ONE_ACCELERATOR": spec.compute_profile.accelerator.value,
                "SCIENTIST_ONE_ACCELERATOR_MEMORY_LIMIT_BYTES": str(
                    spec.compute_profile.accelerator_memory_limit_bytes
                ),
                "SCIENTIST_ONE_DISK_LIMIT_BYTES": str(
                    spec.compute_profile.disk_limit_bytes
                ),
                "SCIENTIST_ONE_EXECUTION_PLAN_SHA256": plan.sha256,
                "SCIENTIST_ONE_MEMORY_LIMIT_BYTES": str(
                    plan.memory_limit_per_worker_bytes
                ),
                "SCIENTIST_ONE_CONCURRENCY": str(plan.concurrency),
                "SCIENTIST_ONE_BATCH_SIZE": str(plan.batch_size),
                "SCIENTIST_ONE_CACHE_KEY": plan.cache_key,
                "SCIENTIST_ONE_CACHE_POLICY": spec.cache_policy.value,
                "SCIENTIST_ONE_CHECKPOINT_POLICY": spec.checkpoint_policy.value,
                "SCIENTIST_ONE_RESUME_FROM_CHECKPOINT_SHA256": marker or "NONE",
            }
        )
        return MappingProxyType(environment)

    def _scrubbed_environment(self, spec: FrozenRunSpec, directory: Path) -> Mapping[str, str]:
        with self._lock:
            job_id = self._spec_jobs.get(spec.sha256)
            job = self._jobs.get(job_id) if job_id is not None else None
        if job is None or job.directory != directory:
            raise ExperimentIntegrityError("local execution plan is unavailable")
        return self._environment_for_job(job)

    def _resolve_target_executable(self, spec: FrozenRunSpec) -> Path:
        candidate = Path(spec.argv[0])
        if candidate.is_absolute():
            resolved = candidate
        elif len(candidate.parts) > 1:
            resolved = resolve_confined(
                self._root,
                candidate,
                must_exist=True,
                expected_kind="file",
                reject_hardlinks=True,
            )
        else:
            found = shutil.which(spec.argv[0], path="/usr/bin:/bin")
            if found is None:
                raise ExperimentError("allowlisted target executable is unavailable")
            resolved = Path(found)
        if not resolved.is_absolute() or not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise ExperimentError("allowlisted target executable is not executable")
        return resolved

    def _validate_required_target(self, spec: FrozenRunSpec) -> None:
        if self._isolation_mode is not LocalMacIsolationMode.REQUIRED:
            return
        if not Path(spec.argv[0]).name.lower().startswith("python"):
            return
        if len(spec.argv) < 5 or spec.argv[1:4] != ("-I", "-S", "-B"):
            raise ExperimentError(
                "direct Python target requires the exact isolated script form"
            )
        resolve_confined(
            self._root,
            spec.argv[4],
            must_exist=True,
            expected_kind="file",
            reject_hardlinks=True,
        )

    def _normalize_execution_input_paths(
        self,
        spec: FrozenRunSpec,
        input_artifact_paths: Mapping[str, str] | None,
    ) -> Mapping[str, str]:
        if self._execution_mode is LocalMacExecutionMode.INJECTED_DIAGNOSTIC:
            if input_artifact_paths is not None:
                raise ExperimentError(
                    "diagnostic execution rejects scientific input bindings"
                )
            return MappingProxyType({})
        if input_artifact_paths is None:
            raise ExperimentError(
                "bound local execution requires exact code, data, configuration, and evaluator paths"
            )
        if not isinstance(input_artifact_paths, Mapping) or set(
            input_artifact_paths
        ) != set(LOCAL_MAC_EXECUTION_INPUT_KINDS):
            raise ExperimentError(
                "bound local execution requires exact code, data, configuration, and evaluator paths"
            )
        normalized: dict[str, str] = {}
        for kind in LOCAL_MAC_EXECUTION_INPUT_KINDS:
            value = input_artifact_paths[kind]
            if not isinstance(value, str) or not value:
                raise ExperimentError("execution input paths must be non-empty text")
            resolved = resolve_confined(
                self._root,
                value,
                must_exist=True,
                expected_kind="file",
                reject_hardlinks=True,
            )
            normalized[kind] = resolved.relative_to(self._root).as_posix()
        if (
            not Path(spec.argv[0]).name.lower().startswith("python")
            or len(spec.argv) < 5
            or normalized["code"]
            != resolve_confined(
                self._root,
                spec.argv[4],
                must_exist=True,
                expected_kind="file",
                reject_hardlinks=True,
            ).relative_to(self._root).as_posix()
        ):
            raise ExperimentError(
                "bound local execution requires its Python script to be the exact code input"
            )
        return MappingProxyType(normalized)

    def _local_job_suffix(self) -> str:
        if self._execution_mode is LocalMacExecutionMode.INJECTED_DIAGNOSTIC:
            return "-diagnostic"
        if self._isolation_mode is LocalMacIsolationMode.REQUIRED:
            return "-isolated"
        return ""

    def _execution_mode_payload(self) -> dict[str, Any]:
        diagnostic = (
            self._execution_mode is LocalMacExecutionMode.INJECTED_DIAGNOSTIC
        )
        return {
            "schema_version": LOCAL_MAC_EXECUTION_MODE_SCHEMA,
            "execution_mode": self._execution_mode.value,
            "isolation_mode": self._isolation_mode.value,
            "validation_status": (
                ValidationStatus.UNTESTED.value
                if diagnostic
                else ValidationStatus.VALIDATED_LOCAL.value
            ),
            "execution_input_binding_required": not diagnostic,
            "diagnostic_unpromotable": diagnostic,
            "scientific_evidence": False,
        }

    def _require_persisted_execution_mode(self, directory: Path) -> None:
        payload = read_confined_bytes(
            directory,
            "execution-mode.json",
            reject_hardlinks=True,
            max_bytes=MAX_OUTPUT_MANIFEST_BYTES,
        )
        assert payload is not None
        try:
            value = safe_json_loads(payload, max_bytes=MAX_OUTPUT_MANIFEST_BYTES)
        except ValidationError as exc:
            raise ExperimentIntegrityError(
                "persisted local execution mode is malformed"
            ) from exc
        if (
            not isinstance(value, Mapping)
            or dict(value) != self._execution_mode_payload()
            or payload != canonical_json_bytes(value) + b"\n"
        ):
            raise ExperimentIntegrityError(
                "persisted local execution mode differs from this backend"
            )

    def _create_job_directory(self, job_id: str) -> Path:
        parent_relative = Path(
            ".scientist-one-build", "experiments", "local-mac"
        )
        parent_fd = open_confined_directory_fd(
            self._root,
            parent_relative,
            create=False,
        )
        try:
            try:
                os.mkdir(job_id, mode=0o700, dir_fd=parent_fd)
            except FileExistsError as exc:
                raise SubmissionConflictError(
                    "local job directory already exists; use explicit recovery"
                ) from exc
            except OSError as exc:
                raise ExperimentError("local job directory creation failed") from exc
            os.fsync(parent_fd)
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            directory_fd = os.open(job_id, flags, dir_fd=parent_fd)
            try:
                metadata = os.fstat(directory_fd)
                if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077:
                    raise ExperimentIntegrityError(
                        "local job directory permissions are not private"
                    )
            finally:
                os.close(directory_fd)
        finally:
            os.close(parent_fd)
        return self._root / parent_relative / job_id

    @staticmethod
    def _read_held_descriptor(descriptor: int, *, maximum_bytes: int) -> bytes:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > maximum_bytes
        ):
            raise ExperimentIntegrityError(
                "staged execution input is not a bounded private regular file"
            )
        chunks: list[bytes] = []
        offset = 0
        while offset < metadata.st_size:
            chunk = os.pread(
                descriptor,
                min(1024 * 1024, metadata.st_size - offset),
                offset,
            )
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
        payload = b"".join(chunks)
        final = os.fstat(descriptor)
        def stable_metadata(value: os.stat_result) -> tuple[int, ...]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_nlink,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )
        if (
            len(payload) != metadata.st_size
            or stable_metadata(final) != stable_metadata(metadata)
        ):
            raise ExperimentIntegrityError(
                "staged execution input changed while held"
            )
        return payload

    def _stage_execution_inputs(
        self,
        spec: FrozenRunSpec,
        directory: Path,
        input_artifact_paths: Mapping[str, str],
    ) -> tuple[Mapping[str, str], str | None]:
        if not input_artifact_paths:
            return MappingProxyType({}), None
        expected = {
            "code": spec.code_sha256,
            "data": spec.data_sha256,
            "configuration": spec.configuration_sha256,
            "evaluator": spec.evaluator_sha256,
        }
        relative_job = directory.relative_to(self._root)
        staged_names: dict[str, str] = {}
        staged_records: list[dict[str, Any]] = []
        for kind in LOCAL_MAC_EXECUTION_INPUT_KINDS:
            payload = read_confined_bytes(
                self._root,
                input_artifact_paths[kind],
                reject_hardlinks=True,
                max_bytes=MAX_OUTPUT_ARTIFACT_BYTES,
            )
            assert payload is not None
            digest = hashlib.sha256(payload).hexdigest()
            if digest != expected[kind]:
                raise ExperimentIntegrityError(
                    f"{kind} bytes differ from the frozen run identity"
                )
            suffix = ".py" if kind == "code" else ".bin"
            name = f"frozen-input-{kind}{suffix}"
            atomic_write_bytes(
                self._root,
                relative_job / name,
                payload,
                immutable=True,
                mode=0o400,
            )
            staged_names[kind] = name
            staged_records.append(
                {
                    "kind": kind,
                    "sha256": digest,
                    "size": len(payload),
                    "staged_name": name,
                }
            )
        binding = {
            "schema_version": LOCAL_MAC_EXECUTION_INPUT_BINDING_SCHEMA,
            "spec_sha256": spec.sha256,
            "inputs": staged_records,
            "consumption": "PARENT_HELD_READ_DESCRIPTORS",
            "scientific_evidence": False,
        }
        binding_bytes = canonical_json_bytes(binding) + b"\n"
        atomic_write_bytes(
            self._root,
            relative_job / "execution-input-binding.json",
            binding_bytes,
            immutable=True,
            mode=0o400,
        )
        return (
            MappingProxyType(staged_names),
            hashlib.sha256(binding_bytes).hexdigest(),
        )

    def _load_staged_execution_inputs(
        self,
        spec: FrozenRunSpec,
        directory: Path,
    ) -> tuple[Mapping[str, str], str | None]:
        binding_bytes = read_confined_bytes(
            directory,
            "execution-input-binding.json",
            reject_hardlinks=True,
            max_bytes=MAX_OUTPUT_MANIFEST_BYTES,
            missing_ok=True,
        )
        if binding_bytes is None:
            return MappingProxyType({}), None
        try:
            value = safe_json_loads(
                binding_bytes,
                max_bytes=MAX_OUTPUT_MANIFEST_BYTES,
            )
        except ValidationError as exc:
            raise ExperimentIntegrityError(
                "persisted execution input binding is malformed"
            ) from exc
        if (
            not isinstance(value, Mapping)
            or set(value)
            != {
                "schema_version",
                "spec_sha256",
                "inputs",
                "consumption",
                "scientific_evidence",
            }
            or value.get("schema_version")
            != LOCAL_MAC_EXECUTION_INPUT_BINDING_SCHEMA
            or value.get("spec_sha256") != spec.sha256
            or value.get("consumption") != "PARENT_HELD_READ_DESCRIPTORS"
            or value.get("scientific_evidence") is not False
            or binding_bytes != canonical_json_bytes(value) + b"\n"
            or not isinstance(value.get("inputs"), list)
        ):
            raise ExperimentIntegrityError(
                "persisted execution input binding is not authoritative"
            )
        expected_hashes = {
            "code": spec.code_sha256,
            "data": spec.data_sha256,
            "configuration": spec.configuration_sha256,
            "evaluator": spec.evaluator_sha256,
        }
        names: dict[str, str] = {}
        for item in value["inputs"]:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"kind", "sha256", "size", "staged_name"}
                or item.get("kind") not in expected_hashes
                or item["kind"] in names
                or item.get("sha256") != expected_hashes[item["kind"]]
                or isinstance(item.get("size"), bool)
                or not isinstance(item.get("size"), int)
                or item["size"] < 0
                or not isinstance(item.get("staged_name"), str)
            ):
                raise ExperimentIntegrityError(
                    "persisted execution input entry is malformed"
                )
            payload = read_confined_bytes(
                directory,
                item["staged_name"],
                reject_hardlinks=True,
                max_bytes=MAX_OUTPUT_ARTIFACT_BYTES,
            )
            assert payload is not None
            if (
                len(payload) != item["size"]
                or hashlib.sha256(payload).hexdigest() != item["sha256"]
            ):
                raise ExperimentIntegrityError(
                    "persisted staged execution input changed"
                )
            names[item["kind"]] = item["staged_name"]
        if set(names) != set(LOCAL_MAC_EXECUTION_INPUT_KINDS):
            raise ExperimentIntegrityError(
                "persisted execution input set is incomplete"
            )
        return (
            MappingProxyType(names),
            hashlib.sha256(binding_bytes).hexdigest(),
        )

    def _open_execution_descriptors(
        self,
        job: _LocalJob,
    ) -> tuple[int, Mapping[str, int]]:
        relative_job = job.directory.relative_to(self._root)
        directory_fd = open_confined_directory_fd(
            self._root,
            relative_job,
            create=False,
        )
        input_fds: dict[str, int] = {}
        try:
            expected = {
                "code": job.spec.code_sha256,
                "data": job.spec.data_sha256,
                "configuration": job.spec.configuration_sha256,
                "evaluator": job.spec.evaluator_sha256,
            }
            for kind, name in job.staged_input_names.items():
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(name, flags, dir_fd=directory_fd)
                try:
                    payload = self._read_held_descriptor(
                        descriptor,
                        maximum_bytes=MAX_OUTPUT_ARTIFACT_BYTES,
                    )
                    if hashlib.sha256(payload).hexdigest() != expected[kind]:
                        raise ExperimentIntegrityError(
                            f"staged {kind} input differs from the frozen run"
                        )
                except Exception:
                    os.close(descriptor)
                    raise
                input_fds[kind] = descriptor
            if bool(input_fds) != bool(job.execution_input_binding_sha256):
                raise ExperimentIntegrityError(
                    "local execution input binding is incomplete"
                )
            return directory_fd, MappingProxyType(input_fds)
        except Exception:
            for descriptor in input_fds.values():
                os.close(descriptor)
            os.close(directory_fd)
            raise

    @staticmethod
    def _resource_enforcement_status(spec: FrozenRunSpec) -> dict[str, Any]:
        return {
            "cpu_rlimit": "NOT_ENFORCED_PARENT_WALL_TIMEOUT_ONLY",
            "file_size_rlimit": (
                "NOT_ENFORCED_HASHED_OUTPUT_SIZE_VALIDATION_ONLY"
            ),
            "memory_rlimit": (
                "NOT_ENFORCED_ADAPTIVE_PLAN_ONLY_MACOS_DYLD_INCOMPATIBLE"
            ),
            "nofile_rlimit": "NOT_ENFORCED",
            "core_rlimit": "NOT_ENFORCED",
            "parent_timeout_seconds": spec.timeout_seconds,
            "maximum_output_artifact_bytes": MAX_OUTPUT_ARTIFACT_BYTES,
        }

    def _seatbelt_profile(
        self,
        job: _LocalJob,
        *,
        target_executable: Path,
    ) -> bytes:
        profile = [
            f"; {LOCAL_MAC_SANDBOX_PROFILE_SCHEMA}",
            "(version 1)",
            "(deny default)",
            "(deny network*)",
            "(allow file-read*)",
            "(allow file-write*",
            f'    (subpath "{_seatbelt_literal(job.directory)}")',
            '    (literal "/dev/null")',
            ")",
            "(allow process-exec",
            f'    (literal "{_seatbelt_literal(target_executable)}")',
            ")",
            "(allow process-info*)",
            "(allow sysctl-read)",
            '(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))',
        ]
        return ("\n".join(profile) + "\n").encode("utf-8")

    def _isolated_launch_components(
        self,
        job: _LocalJob,
        environment: Mapping[str, str],
        *,
        launch_index: int,
        exact_target_argv: tuple[str, ...] | None = None,
    ) -> tuple[bytes, dict[str, Any], tuple[str, ...]]:
        if job.execution_plan is None:
            raise ExperimentIntegrityError("isolated launch has no execution plan")
        if not 1 <= launch_index <= LOCAL_MAC_MAX_ISOLATED_LAUNCHES:
            raise ExperimentError("isolated launch count exceeds its safety bound")
        self._require_isolation_available()
        cwd = resolve_confined(
            self._root,
            job.spec.working_directory,
            must_exist=True,
            expected_kind="directory",
            allow_root=True,
        )
        target_executable = self._resolve_target_executable(job.spec)
        sandbox_executable = Path(LOCAL_MAC_SANDBOX_EXECUTABLE)
        profile = self._seatbelt_profile(
            job,
            target_executable=target_executable,
        )
        relative_job = job.directory.relative_to(self._root)
        profile_name = "local-isolation-seatbelt.sb"
        resource_enforcement = self._resource_enforcement_status(job.spec)
        if exact_target_argv is None:
            exact_target_argv = (str(target_executable), *job.spec.argv[1:])
        if (
            not exact_target_argv
            or exact_target_argv[0] != str(target_executable)
        ):
            raise ExperimentIntegrityError(
                "isolated launch target differs from the validated executable"
            )
        try:
            inline_profile = profile.decode("utf-8")
        except UnicodeDecodeError as exc:  # pragma: no cover - internal invariant
            raise ExperimentIntegrityError(
                "Seatbelt profile is not exact UTF-8 text"
            ) from exc
        launch_argv = (
            str(sandbox_executable),
            "-p",
            inline_profile,
            "--",
            *exact_target_argv,
        )
        evidence = {
            "schema_version": LOCAL_MAC_ISOLATION_SCHEMA,
            "backend_id": self.backend_id,
            "isolation_mode": LocalMacIsolationMode.REQUIRED.value,
            "evidence_scope": (
                "HASH_BOUND_INTENDED_LAUNCH_TECHNICAL_RECORD;"
                "NOT_SAME_USER_RACE_PROOF;NOT_SCIENTIFIC_AUTHORITY"
            ),
            "launch_index": launch_index,
            "spec_sha256": job.spec.sha256,
            "execution_plan_sha256": job.execution_plan.sha256,
            "compute_profile_sha256": job.spec.compute_profile.sha256,
            "resource_estimate_sha256": job.spec.resource_estimate.sha256,
            "sandbox_profile_path": profile_name,
            "sandbox_profile_sha256": hashlib.sha256(profile).hexdigest(),
            "sandbox_profile_consumption": "INLINE_EXACT_BYTES",
            "sandbox_executable_path": str(sandbox_executable),
            "sandbox_executable_sha256": _stable_file_sha256(
                sandbox_executable,
                "Seatbelt executable",
            ),
            "target_executable_path": str(target_executable),
            "target_executable_sha256": _stable_file_sha256(
                target_executable,
                "target executable",
            ),
            "working_directory": job.spec.working_directory,
            "resolved_working_directory": str(cwd),
            "boundary_claims": {
                "network_denied_by_seatbelt": True,
                "writes_confined_to_job_directory": True,
                "process_exec_confined_to_exact_target": True,
                "filesystem_read_isolation": False,
                "os_resource_limits_enforced": False,
            },
            "resource_enforcement": resource_enforcement,
            "environment": dict(environment),
            "target_argv": list(exact_target_argv),
            "launch_argv": list(launch_argv),
            "scientific_evidence": False,
            "network_isolation_attested": False,
        }
        atomic_write_bytes(
            self._root,
            relative_job / profile_name,
            profile,
            immutable=True,
        )
        return profile, evidence, launch_argv

    def _prepare_isolated_launch(
        self,
        job: _LocalJob,
        environment: Mapping[str, str],
        *,
        exact_target_argv: tuple[str, ...],
    ) -> tuple[str, ...]:
        _, evidence, launch_argv = self._isolated_launch_components(
            job,
            environment,
            launch_index=job.execution_count,
            exact_target_argv=exact_target_argv,
        )
        relative_job = job.directory.relative_to(self._root)
        evidence_name = f"local-isolation-launch-{job.execution_count}.json"
        atomic_write_json(
            self._root,
            relative_job / evidence_name,
            evidence,
            immutable=True,
        )
        digest = hashlib.sha256(canonical_json_bytes(evidence) + b"\n").hexdigest()
        job.isolation_launch_evidence_sha256s = (
            *job.isolation_launch_evidence_sha256s,
            digest,
        )
        return launch_argv

    def _revalidate_isolated_launches(self, job: _LocalJob) -> None:
        if self._isolation_mode is not LocalMacIsolationMode.REQUIRED:
            return
        try:
            names = tuple(os.listdir(job.directory))
        except OSError as exc:
            raise ExperimentIntegrityError(
                "isolated launch directory cannot be enumerated"
            ) from exc
        prefix = "local-isolation-launch-"
        suffix = ".json"
        indexed: list[tuple[int, str]] = []
        for name in names:
            if not name.startswith(prefix):
                continue
            if not name.endswith(suffix):
                raise ExperimentIntegrityError("isolated launch evidence name is malformed")
            raw_index = name[len(prefix) : -len(suffix)]
            if not raw_index.isascii() or not raw_index.isdigit():
                raise ExperimentIntegrityError("isolated launch evidence index is malformed")
            index = int(raw_index)
            indexed.append((index, name))
        indexed.sort()
        if not indexed or len(indexed) > LOCAL_MAC_MAX_ISOLATED_LAUNCHES:
            raise ExperimentIntegrityError("required isolated launch evidence is absent")
        if tuple(index for index, _ in indexed) != tuple(range(1, len(indexed) + 1)):
            raise ExperimentIntegrityError("isolated launch evidence sequence is incomplete")
        digests: list[str] = []
        relative_job = job.directory.relative_to(self._root)
        for index, name in indexed:
            payload = read_confined_bytes(
                self._root,
                relative_job / name,
                reject_hardlinks=True,
                max_bytes=MAX_OUTPUT_MANIFEST_BYTES,
            )
            assert payload is not None
            try:
                actual = safe_json_loads(payload, max_bytes=MAX_OUTPUT_MANIFEST_BYTES)
            except ValidationError as exc:
                raise ExperimentIntegrityError(
                    "isolated launch evidence is malformed"
                ) from exc
            if not isinstance(actual, Mapping):
                raise ExperimentIntegrityError("isolated launch evidence is not an object")
            environment = actual.get("environment")
            if not isinstance(environment, Mapping) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in environment.items()
            ):
                raise ExperimentIntegrityError("isolated launch environment is malformed")
            resume_marker = environment.get(
                "SCIENTIST_ONE_RESUME_FROM_CHECKPOINT_SHA256"
            )
            if index == 1:
                if resume_marker != "NONE":
                    raise ExperimentIntegrityError(
                        "initial isolated launch has an invalid resume marker"
                    )
            elif resume_marker == "NONE":
                raise ExperimentIntegrityError(
                    "resumed isolated launch is missing its checkpoint binding"
                )
            else:
                try:
                    validate_sha256(resume_marker, "isolated launch resume marker")
                except ValidationError as exc:
                    raise ExperimentIntegrityError(
                        "isolated launch resume marker is malformed"
                    ) from exc
            expected_environment = self._environment_for_job(
                job,
                resume_marker=resume_marker,
            )
            descriptor_environment = {
                key: value
                for key, value in environment.items()
                if key.startswith("SCIENTIST_ONE_INPUT_")
                or key == "SCIENTIST_ONE_JOB_DIR_FD"
            }
            expected_descriptor_keys = {"SCIENTIST_ONE_JOB_DIR_FD"}
            if job.execution_input_binding_sha256 is not None:
                expected_descriptor_keys.update(
                    f"SCIENTIST_ONE_INPUT_{kind.upper()}_FD"
                    for kind in LOCAL_MAC_EXECUTION_INPUT_KINDS
                )
            if any(
                not value.isascii() or not value.isdigit() or int(value) < 3
                for value in descriptor_environment.values()
            ) or set(descriptor_environment) != expected_descriptor_keys:
                raise ExperimentIntegrityError(
                    "isolated launch descriptor environment is malformed"
                )
            if {
                key: value
                for key, value in environment.items()
                if key not in descriptor_environment
            } != dict(expected_environment):
                raise ExperimentIntegrityError(
                    "isolated launch environment changed"
                )
            target_argv = actual.get("target_argv")
            if (
                not isinstance(target_argv, list)
                or not target_argv
                or any(not isinstance(item, str) for item in target_argv)
            ):
                raise ExperimentIntegrityError(
                    "isolated launch target argv is malformed"
                )
            target_executable = self._resolve_target_executable(job.spec)
            expected_target_argv = (
                (
                    str(target_executable),
                    *job.spec.argv[1:4],
                    "-",
                    *job.spec.argv[5:],
                )
                if job.execution_input_binding_sha256 is not None
                else (str(target_executable), *job.spec.argv[1:])
            )
            if tuple(target_argv) != expected_target_argv:
                raise ExperimentIntegrityError(
                    "isolated launch target argv changed"
                )
            _, expected, _ = self._isolated_launch_components(
                job,
                environment,
                launch_index=index,
                exact_target_argv=tuple(target_argv),
            )
            if canonical_json_bytes(actual) != canonical_json_bytes(expected):
                raise ExperimentIntegrityError(
                    "isolated launch evidence changed or no longer matches its exact launch"
                )
            digests.append(hashlib.sha256(payload).hexdigest())
        job.isolation_launch_evidence_sha256s = tuple(digests)
        job.execution_count = len(digests)

    @staticmethod
    def _capture_terminal_pipe(
        pipe: Any,
        maximum_bytes: int,
        result: dict[str, Any],
        prefix: str,
    ) -> None:
        """Retain partial bytes and an explicit incomplete flag on drain error."""

        retained = bytearray()
        total = 0
        complete = False
        try:
            while True:
                chunk = pipe.read(64 * 1024)
                if not chunk:
                    complete = True
                    break
                total += len(chunk)
                retained.extend(chunk[: max(0, maximum_bytes - len(retained))])
        except Exception:
            # No exception text: OS/child-controlled details can contain secrets.
            complete = False
        finally:
            try:
                pipe.close()
            except Exception:
                complete = False
            result[prefix] = bytes(retained)
            result[f"{prefix}_truncated"] = total > maximum_bytes
            result[f"{prefix}_complete"] = complete

    @staticmethod
    def _capture_pipe(
        pipe: Any,
        maximum_bytes: int,
        result: dict[str, Any],
        prefix: str,
    ) -> None:
        retained = bytearray()
        total = 0
        try:
            while True:
                chunk = pipe.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if len(retained) < maximum_bytes:
                    retained.extend(chunk[: maximum_bytes - len(retained)])
        finally:
            pipe.close()
        result[prefix] = bytes(retained)
        result[f"{prefix}_truncated"] = total > maximum_bytes

    @staticmethod
    def _validated_active_process(
        process: subprocess.Popen[bytes],
    ) -> _ActiveLocalProcess:
        pid = process.pid
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
            raise ExperimentIntegrityError("spawned local process PID is invalid")
        try:
            process_group_id = os.getpgid(pid)
            session_id = os.getsid(pid)
            caller_process_group = os.getpgrp()
        except (AttributeError, OSError) as exc:
            raise ExperimentIntegrityError(
                "spawned local process group cannot be validated"
            ) from exc
        if (
            process_group_id != pid
            or session_id != pid
            or process_group_id == caller_process_group
        ):
            raise ExperimentIntegrityError(
                "spawned local process does not own a distinct validated session group"
            )
        return _ActiveLocalProcess(process, process_group_id, session_id)

    @staticmethod
    def _process_group_exists(process_group_id: int) -> bool:
        try:
            os.killpg(process_group_id, 0)
        except ProcessLookupError:
            return False
        except PermissionError as exc:
            raise ExperimentIntegrityError(
                "local process-group liveness cannot be verified"
            ) from exc
        return True

    @classmethod
    def _wait_for_process_group_exit(
        cls,
        process_group_id: int,
        timeout_seconds: float,
    ) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while cls._process_group_exists(process_group_id):
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True

    @classmethod
    def _terminate_process_group(cls, active: _ActiveLocalProcess) -> int:
        """Terminate exactly one backend-spawned session group and reap its leader."""

        with active.termination_lock:
            process = active.process
            process_group_id = active.process_group_id
            if (
                process.pid != process_group_id
                or active.session_id != process_group_id
                or process_group_id <= 1
                or process_group_id == os.getpgrp()
            ):
                raise ExperimentIntegrityError(
                    "refusing to terminate an unvalidated or caller-owned process group"
                )
            try:
                os.killpg(process_group_id, signal.SIGTERM)
            except ProcessLookupError:
                pass
            if process.poll() is None:
                try:
                    process.wait(timeout=LOCAL_PROCESS_TERM_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    pass
            if not cls._wait_for_process_group_exit(
                process_group_id,
                LOCAL_PROCESS_TERM_GRACE_SECONDS,
            ):
                try:
                    os.killpg(process_group_id, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                try:
                    process.wait(timeout=LOCAL_PROCESS_KILL_GRACE_SECONDS)
                except subprocess.TimeoutExpired as exc:
                    raise ExperimentIntegrityError(
                        "local process-group leader could not be reaped"
                    ) from exc
            if not cls._wait_for_process_group_exit(
                process_group_id,
                LOCAL_PROCESS_KILL_GRACE_SECONDS,
            ):
                raise ExperimentIntegrityError(
                    "local process group remained live after bounded termination"
                )
            return int(process.returncode if process.returncode is not None else -signal.SIGKILL)

    def _run_subprocess(
        self,
        spec: FrozenRunSpec,
        directory: Path,
        environment: Mapping[str, str],
    ) -> ExecutionResult:
        cwd = resolve_confined(
            self._root,
            spec.working_directory,
            must_exist=True,
            expected_kind="directory",
            allow_root=True,
        )
        process: subprocess.Popen[bytes] | None = None
        active: _ActiveLocalProcess | None = None
        job_id: str | None = None
        directory_fd: int | None = None
        input_fds: Mapping[str, int] = MappingProxyType({})
        terminal_capture = LOCAL_TERMINAL_CAPTURE_METADATA_KEY in spec.metadata
        captured: dict[str, Any] = {}
        timed_out = False
        try:
            with self._lock:
                job_id = self._spec_jobs.get(spec.sha256)
                job = self._jobs.get(job_id) if job_id is not None else None
                if job is None or job.spec is not spec or job.directory != directory:
                    raise ExperimentIntegrityError(
                        "local process has no exact registered job identity"
                    )
            directory_fd, input_fds = self._open_execution_descriptors(job)
            launch_environment = dict(environment)
            launch_environment["SCIENTIST_ONE_JOB_DIR_FD"] = str(directory_fd)
            for kind, descriptor in input_fds.items():
                launch_environment[
                    f"SCIENTIST_ONE_INPUT_{kind.upper()}_FD"
                ] = str(descriptor)
            target_executable = self._resolve_target_executable(spec)
            exact_target_argv = (str(target_executable), *spec.argv[1:])
            if input_fds:
                if set(input_fds) != set(LOCAL_MAC_EXECUTION_INPUT_KINDS):
                    raise ExperimentIntegrityError(
                        "local process lacks a complete held input set"
                    )
                # The validated public command remains the closed isolated
                # script form. Internally, feed the already-open, hash-checked
                # code descriptor to Python as stdin so the interpreter cannot
                # reopen a replaceable staged pathname after validation.
                exact_target_argv = (
                    str(target_executable),
                    *spec.argv[1:4],
                    "-",
                    *spec.argv[5:],
                )
            launch_argv = exact_target_argv
            if self._isolation_mode is LocalMacIsolationMode.REQUIRED:
                with self._lock:
                    self._require_exact_builtin_runner()
                    launch_argv = self._prepare_isolated_launch(
                        job,
                        launch_environment,
                        exact_target_argv=exact_target_argv,
                    )
            pass_fds = (directory_fd, *input_fds.values())
            process = subprocess.Popen(
                list(launch_argv),
                cwd=cwd,
                env=launch_environment,
                stdin=(input_fds["code"] if input_fds else subprocess.DEVNULL),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                pass_fds=pass_fds,
                start_new_session=True,
            )
            if terminal_capture:
                with self._lock:
                    job.terminal_popen_launch_count += 1
            for descriptor in input_fds.values():
                os.close(descriptor)
            input_fds = MappingProxyType({})
            os.close(directory_fd)
            directory_fd = None
            active = self._validated_active_process(process)
            with self._lock:
                job_id = self._spec_jobs.get(spec.sha256)
                job = self._jobs.get(job_id) if job_id is not None else None
                if job is None or job.spec is not spec:
                    raise ExperimentIntegrityError(
                        "spawned local process has no exact registered job identity"
                    )
                if job_id in self._active_processes:
                    raise ExperimentIntegrityError(
                        "local job already owns an active process group"
                    )
                self._active_processes[job_id] = active
                cancelled = job.state is RunState.CANCELLED
            assert process.stdout is not None and process.stderr is not None
            capture_pipe = (
                self._capture_terminal_pipe if terminal_capture else self._capture_pipe
            )
            stdout_thread = threading.Thread(
                target=capture_pipe,
                args=(process.stdout, spec.maximum_stdout_bytes, captured, "stdout"),
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=capture_pipe,
                args=(process.stderr, spec.maximum_stderr_bytes, captured, "stderr"),
                daemon=True,
            )
            stdout_thread.start()
            stderr_thread.start()
            timed_out = False
            if cancelled:
                returncode = self._terminate_process_group(active)
            else:
                try:
                    returncode = process.wait(timeout=spec.timeout_seconds)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    returncode = self._terminate_process_group(active)
            stdout_thread.join(timeout=LOCAL_PROCESS_KILL_GRACE_SECONDS)
            stderr_thread.join(timeout=LOCAL_PROCESS_KILL_GRACE_SECONDS)
            if stdout_thread.is_alive() or stderr_thread.is_alive():
                self._terminate_process_group(active)
                raise ExperimentIntegrityError("subprocess log drain did not terminate")
            result = ExecutionResult(
                returncode=returncode,
                stdout=captured.get("stdout", b""),
                stderr=captured.get("stderr", b""),
                stdout_truncated=bool(captured.get("stdout_truncated", False)),
                stderr_truncated=bool(captured.get("stderr_truncated", False)),
                timed_out=timed_out,
            )
            if terminal_capture:
                job.terminal_result = result
                job.terminal_log_complete = (
                    captured.get("stdout_complete") is True
                    and captured.get("stderr_complete") is True
                )
            return result
        except BaseException:
            if active is not None:
                self._terminate_process_group(active)
            elif process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=LOCAL_PROCESS_TERM_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=LOCAL_PROCESS_KILL_GRACE_SECONDS)
            raise
        finally:
            if terminal_capture and process is not None and process.returncode is not None:
                # Preserve real available partial bytes even when process
                # validation/log capture raises. Completeness remains false.
                job.terminal_result = ExecutionResult(
                    returncode=process.returncode,
                    stdout=captured.get("stdout", b""),
                    stderr=captured.get("stderr", b""),
                    stdout_truncated=bool(captured.get("stdout_truncated", False)),
                    stderr_truncated=bool(captured.get("stderr_truncated", False)),
                    timed_out=timed_out,
                )
                for prefix in ("stdout", "stderr"):
                    complete = captured.get(f"{prefix}_complete")
                    setattr(
                        job, f"terminal_{prefix}_status",
                        "COMPLETE" if complete is True
                        else "INCOMPLETE" if complete is False else "UNAVAILABLE",
                    )
                job.terminal_log_complete = (
                    job.terminal_stdout_status == job.terminal_stderr_status == "COMPLETE"
                )
            for descriptor in input_fds.values():
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if directory_fd is not None:
                try:
                    os.close(directory_fd)
                except OSError:
                    pass
            if process is not None:
                for pipe in (process.stdout, process.stderr):
                    if pipe is not None and not pipe.closed:
                        try:
                            pipe.close()
                        except (OSError, ValueError):
                            pass
            if job_id is not None and active is not None:
                with self._lock:
                    if self._active_processes.get(job_id) is active:
                        del self._active_processes[job_id]

    def submit(
        self,
        spec: FrozenRunSpec,
        *,
        idempotency_key: str,
        input_artifact_paths: Mapping[str, str] | None = None,
    ) -> SubmissionReceipt:
        if not isinstance(spec, FrozenRunSpec):
            raise ExperimentError("spec must be FrozenRunSpec")
        terminal_capture = self._terminal_profile(spec)
        self._validate_local_profile(spec)
        plan = plan_adaptive_execution(
            spec.compute_profile,
            spec.resource_estimate,
            observed_available_memory_bytes=self._observed_available_memory_bytes,
            pending_tasks=len(spec.seeds),
            bytes_per_sample=spec.bytes_per_sample,
            worker_overhead_bytes=spec.worker_overhead_bytes,
            concurrency_cap=self._maximum_concurrency_cap,
        )
        validate_identifier(idempotency_key, "idempotency key")
        validate_command(
            spec.argv,
            allowed_executables=self._allowed_executables,
            root=self._root,
            allowed_python_modules=(),
        )
        self._validate_required_target(spec)
        normalized_inputs = self._normalize_execution_input_paths(
            spec,
            input_artifact_paths,
        )
        if terminal_capture:
            input_size = 0
            for path in normalized_inputs.values():
                payload = read_confined_bytes(
                    self._root, path, reject_hardlinks=True,
                    max_bytes=LOCAL_TERMINAL_MAX_FILE_BYTES,
                )
                assert payload is not None
                input_size += len(payload)
            source_size = input_size + sum(
                len(canonical_json_bytes(value)) + 1
                for value in (spec.to_dict(), plan.to_dict(), self._execution_mode_payload())
            )
            # Fixed staged filenames/four bounded descriptors and dispatch
            # intent use less than 16KiB; reserve that before any dispatch.
            if source_size + 16 * 1024 > LOCAL_TERMINAL_MAX_SOURCE_BYTES:
                raise ExperimentError(
                    "terminal capture inputs exceed the closed byte budget"
                )
        with self._lock:
            previous = self._idempotency.get(idempotency_key)
            if previous is not None:
                prior_sha, job_id = previous
                if prior_sha != spec.sha256:
                    raise SubmissionConflictError("idempotency key names a different run spec")
                if bool(self._jobs[job_id].staged_input_names) != bool(
                    normalized_inputs
                ):
                    raise SubmissionConflictError(
                        "idempotency key changed the execution input binding"
                    )
                if terminal_capture:
                    self.collect_terminal_observation(job_id)
                return self._receipt(
                    self._jobs[job_id],
                    cache_hit=spec.cache_policy is CachePolicy.CONTENT_ADDRESSABLE,
                )
            existing_job_id = self._spec_jobs.get(spec.sha256)
            if existing_job_id is not None:
                if bool(self._jobs[existing_job_id].staged_input_names) != bool(
                    normalized_inputs
                ):
                    raise SubmissionConflictError(
                        "frozen run changed the execution input binding"
                    )
                if spec.cache_policy is CachePolicy.DISABLED:
                    raise SubmissionConflictError(
                        "frozen run was already submitted and content caching is disabled"
                    )
                self._idempotency[idempotency_key] = (spec.sha256, existing_job_id)
                if terminal_capture:
                    self.collect_terminal_observation(existing_job_id)
                return self._receipt(self._jobs[existing_job_id], cache_hit=True)
            prior_run_spec = self._run_specs.get(spec.run_id)
            if prior_run_spec is not None and prior_run_spec != spec.sha256:
                raise SubmissionConflictError("run ID names a different frozen spec")

            suffix = self._local_job_suffix()
            job_id = f"local-{spec.sha256[:20]}{suffix}"
            relative_directory = f".scientist-one-build/experiments/local-mac/{job_id}"
            directory = self._create_job_directory(job_id)
            staged_input_names, input_binding_sha256 = (
                self._stage_execution_inputs(
                    spec,
                    directory,
                    normalized_inputs,
                )
            )
            atomic_write_json(
                self._root,
                f"{relative_directory}/frozen-run-spec.json",
                spec.to_dict(),
                immutable=True,
            )
            atomic_write_json(
                self._root,
                f"{relative_directory}/execution-plan.json",
                plan.to_dict(),
                immutable=True,
            )
            atomic_write_json(
                self._root,
                f"{relative_directory}/execution-mode.json",
                self._execution_mode_payload(),
                immutable=True,
            )
            job = _LocalJob(
                spec=spec,
                idempotency_key=idempotency_key,
                job_id=job_id,
                directory=directory,
                state=RunState.QUEUED,
                execution_plan=plan,
                execution_mode=self._execution_mode,
                execution_input_binding_sha256=input_binding_sha256,
                staged_input_names=staged_input_names,
            )
            self._jobs[job_id] = job
            self._idempotency[idempotency_key] = (spec.sha256, job_id)
            self._spec_jobs[spec.sha256] = job_id
            self._run_specs[spec.run_id] = spec.sha256
            if terminal_capture:
                job.terminal_directory_identity = self._terminal_directory(job)

        if terminal_capture:
            return self._execute_terminal_job(job)

        acquired = self._execution_slots.acquire(timeout=self._queue_timeout_seconds)
        if not acquired:
            with self._lock:
                job.state = RunState.FAILED
                job.reason = "LOCAL_QUEUE_TIMEOUT"
            return self._receipt(job)
        with self._lock:
            if job.state == RunState.CANCELLED:
                self._execution_slots.release()
                return self._receipt(job)
            job.state = RunState.RUNNING
            job.execution_count += 1
        environment = self._scrubbed_environment(spec, directory)
        try:
            try:
                if self._execution_mode is LocalMacExecutionMode.BOUND_BUILTIN:
                    self._require_exact_builtin_runner()
                result = self._execution_runner(spec, directory, environment)
                if not isinstance(result, ExecutionResult):
                    raise ExperimentError("execution runner returned an invalid result")
            except Exception as exc:
                with self._lock:
                    job.state = RunState.FAILED
                    job.reason = f"EXECUTION_EXCEPTION:{type(exc).__name__}"
                if isinstance(exc, (ExperimentError, ExperimentIntegrityError, PathSecurityError)):
                    raise
                return self._receipt(job)
        finally:
            self._execution_slots.release()

        return self._finalize_execution(job, result, log_suffix="")

    def recover(self, spec: FrozenRunSpec, *, idempotency_key: str) -> SubmissionReceipt:
        """Rehydrate a completed or checkpointed local job without executing it.

        Recovery is deliberately explicit.  It accepts only the deterministic
        job directory for the exact frozen spec, revalidates the persisted spec
        and adaptive plan, and then verifies either all returned artifacts or a
        bound checkpoint.  It never retries work and never selects a backend.
        """

        if not isinstance(spec, FrozenRunSpec):
            raise ExperimentError("spec must be FrozenRunSpec")
        if self._terminal_profile(spec):
            observation = self.recover_terminal_observation(
                spec, idempotency_key=idempotency_key,
            )
            return self._receipt(self._jobs[observation.job_id])
        self._validate_local_profile(spec)
        validate_identifier(idempotency_key, "idempotency key")
        validate_command(
            spec.argv,
            allowed_executables=self._allowed_executables,
            root=self._root,
            allowed_python_modules=(),
        )
        self._validate_required_target(spec)
        with self._lock:
            previous = self._idempotency.get(idempotency_key)
            if previous is not None:
                prior_sha, job_id = previous
                if prior_sha != spec.sha256:
                    raise SubmissionConflictError("idempotency key names a different run spec")
                return self._receipt(
                    self._jobs[job_id],
                    cache_hit=spec.cache_policy is CachePolicy.CONTENT_ADDRESSABLE,
                )
            existing_job_id = self._spec_jobs.get(spec.sha256)
            if existing_job_id is not None:
                if spec.cache_policy is CachePolicy.DISABLED:
                    raise SubmissionConflictError(
                        "frozen run was already recovered and content caching is disabled"
                    )
                self._idempotency[idempotency_key] = (spec.sha256, existing_job_id)
                return self._receipt(self._jobs[existing_job_id], cache_hit=True)

        suffix = self._local_job_suffix()
        job_id = f"local-{spec.sha256[:20]}{suffix}"
        relative_directory = f".scientist-one-build/experiments/local-mac/{job_id}"
        directory = secure_directory(self._root, relative_directory, create=False)
        self._require_persisted_execution_mode(directory)
        frozen_payload = read_confined_bytes(
            directory,
            "frozen-run-spec.json",
            reject_hardlinks=True,
            max_bytes=MAX_OUTPUT_MANIFEST_BYTES,
        )
        try:
            persisted_spec = safe_json_loads(
                frozen_payload,
                max_bytes=MAX_OUTPUT_MANIFEST_BYTES,
            )
        except ValidationError as exc:
            raise ExperimentIntegrityError("persisted frozen run spec is malformed") from exc
        if canonical_json_bytes(persisted_spec) != canonical_json_bytes(spec.to_dict()):
            raise ExperimentIntegrityError("persisted frozen run spec does not match recovery input")
        plan_payload = read_confined_bytes(
            directory,
            "execution-plan.json",
            reject_hardlinks=True,
            max_bytes=MAX_OUTPUT_MANIFEST_BYTES,
        )
        try:
            persisted_plan = AdaptiveExecutionPlan.from_mapping(
                safe_json_loads(plan_payload, max_bytes=MAX_OUTPUT_MANIFEST_BYTES)
            )
        except ValidationError as exc:
            raise ExperimentIntegrityError("persisted execution plan is malformed") from exc
        _validate_adaptive_plan_binding(
            persisted_plan,
            spec.compute_profile,
            spec.resource_estimate,
            pending_tasks=len(spec.seeds),
            bytes_per_sample=spec.bytes_per_sample,
            worker_overhead_bytes=spec.worker_overhead_bytes,
        )
        staged_input_names, input_binding_sha256 = (
            self._load_staged_execution_inputs(spec, directory)
        )
        if (
            self._execution_mode is LocalMacExecutionMode.BOUND_BUILTIN
            and (
                input_binding_sha256 is None
                or set(staged_input_names) != set(LOCAL_MAC_EXECUTION_INPUT_KINDS)
            )
        ):
            raise ExperimentIntegrityError(
                "bound local recovery requires the complete execution input binding"
            )
        if (
            self._execution_mode is LocalMacExecutionMode.INJECTED_DIAGNOSTIC
            and (input_binding_sha256 is not None or staged_input_names)
        ):
            raise ExperimentIntegrityError(
                "diagnostic local recovery cannot claim an execution input binding"
            )
        job = _LocalJob(
            spec=spec,
            idempotency_key=idempotency_key,
            job_id=job_id,
            directory=directory,
            execution_plan=persisted_plan,
            execution_mode=self._execution_mode,
            execution_input_binding_sha256=input_binding_sha256,
            staged_input_names=staged_input_names,
        )
        if self._isolation_mode is LocalMacIsolationMode.REQUIRED:
            try:
                self._revalidate_isolated_launches(job)
            except (ValidationError, PathSecurityError) as exc:
                raise ExperimentIntegrityError(
                    "persisted isolated launch evidence failed validation"
                ) from exc
        manifest_payload = read_confined_bytes(
            directory,
            "output-manifest.json",
            reject_hardlinks=True,
            max_bytes=MAX_OUTPUT_MANIFEST_BYTES,
            missing_ok=True,
        )
        checkpoint_payload = read_confined_bytes(
            directory,
            "checkpoint.json",
            reject_hardlinks=True,
            max_bytes=MAX_OUTPUT_MANIFEST_BYTES,
            missing_ok=True,
        )
        if manifest_payload is not None:
            self._capture_and_validate_manifest(job, first_capture=True)
            job.state = RunState.SUCCEEDED
            job.reason = (
                "RECOVERED_INJECTED_DIAGNOSTIC_UNTESTED_UNPROMOTABLE"
                if self._execution_mode
                is LocalMacExecutionMode.INJECTED_DIAGNOSTIC
                else (
                    "RECOVERED_VERIFIED_OUTPUTS_OS_ISOLATION_UNATTESTED_NON_EVIDENTIARY"
                    if spec.evidence_class
                    is EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE
                    else "RECOVERED_VERIFIED_OUTPUTS"
                )
            )
        elif checkpoint_payload is not None:
            if spec.checkpoint_policy is CheckpointPolicy.DISABLED:
                raise ExperimentIntegrityError("persisted checkpoint is forbidden by the run spec")
            current_usable_memory = min(
                spec.compute_profile.memory_limit_bytes,
                int(
                    self._observed_available_memory_bytes
                    * spec.compute_profile.maximum_memory_fraction
                ),
            )
            current_concurrency_cap = min(
                spec.compute_profile.maximum_concurrency,
                self._maximum_concurrency_cap,
                len(spec.seeds),
            )
            if (
                persisted_plan.usable_memory_bytes > current_usable_memory
                or persisted_plan.concurrency > current_concurrency_cap
            ):
                raise ExperimentIntegrityError(
                    "checkpoint execution plan exceeds the current local host envelope"
                )
            (
                job.checkpoint_sha256,
                job.checkpoint_plan_bound,
            ) = self._bound_checkpoint_sha256(job)
            job.state = RunState.PREEMPTED
            job.reason = "RECOVERED_BOUND_CHECKPOINT"
        else:
            raise ExperimentError("no completed outputs or checkpoint are available for recovery")

        with self._lock:
            previous = self._idempotency.get(idempotency_key)
            if previous is not None:
                prior_sha, prior_job_id = previous
                if prior_sha != spec.sha256:
                    raise SubmissionConflictError("idempotency key names a different run spec")
                return self._receipt(
                    self._jobs[prior_job_id],
                    cache_hit=spec.cache_policy is CachePolicy.CONTENT_ADDRESSABLE,
                )
            existing_job_id = self._spec_jobs.get(spec.sha256)
            if existing_job_id is not None:
                raise SubmissionConflictError("frozen run was concurrently registered")
            prior_run_spec = self._run_specs.get(spec.run_id)
            if prior_run_spec is not None and prior_run_spec != spec.sha256:
                raise SubmissionConflictError("run ID names a different frozen spec")
            self._jobs[job_id] = job
            self._idempotency[idempotency_key] = (spec.sha256, job_id)
            self._spec_jobs[spec.sha256] = job_id
            self._run_specs[spec.run_id] = spec.sha256
        return self._receipt(
            job,
            cache_hit=(
                job.state is RunState.SUCCEEDED
                and spec.cache_policy is CachePolicy.CONTENT_ADDRESSABLE
            ),
        )

    def _bound_checkpoint_sha256(
        self,
        job: _LocalJob,
        *,
        allow_legacy_non_evidentiary: bool = False,
    ) -> tuple[str, bool]:
        checkpoint = read_confined_bytes(
            job.directory,
            "checkpoint.json",
            reject_hardlinks=True,
            max_bytes=MAX_OUTPUT_MANIFEST_BYTES,
        )
        assert checkpoint is not None
        checkpoint_value = safe_json_loads(checkpoint)
        if not isinstance(checkpoint_value, Mapping):
            raise ExperimentError("checkpoint must be an object")
        if job.execution_plan is None:
            raise ExperimentIntegrityError("checkpoint has no bound execution plan")
        if (
            checkpoint_value.get("run_id") != job.spec.run_id
            or checkpoint_value.get("spec_sha256") != job.spec.sha256
        ):
            raise ExperimentIntegrityError("checkpoint binding mismatch")
        actual_plan_sha256 = checkpoint_value.get("execution_plan_sha256")
        plan_bound = actual_plan_sha256 == job.execution_plan.sha256
        if not plan_bound and not (
            actual_plan_sha256 is None
            and allow_legacy_non_evidentiary
            and job.spec.evidence_class is EvidenceClass.NON_EVIDENTIARY
        ):
            raise ExperimentIntegrityError("checkpoint execution-plan binding mismatch")
        return hashlib.sha256(checkpoint).hexdigest(), plan_bound

    def _finalize_execution(
        self,
        job: _LocalJob,
        result: ExecutionResult,
        *,
        log_suffix: str,
    ) -> SubmissionReceipt:
        spec = job.spec
        job_id = job.job_id
        stdout_name = f"stdout{log_suffix}.log"
        stderr_name = f"stderr{log_suffix}.log"
        atomic_write_bytes(
            self._root,
            f".scientist-one-build/experiments/local-mac/{job_id}/{stdout_name}",
            result.stdout[: spec.maximum_stdout_bytes],
            immutable=True,
        )
        atomic_write_bytes(
            self._root,
            f".scientist-one-build/experiments/local-mac/{job_id}/{stderr_name}",
            result.stderr[: spec.maximum_stderr_bytes],
            immutable=True,
        )
        with self._lock:
            # A concurrent cancellation remains terminal even if an execution
            # runner returns afterward.  In particular, a late valid manifest
            # cannot turn cancelled work back into scientific evidence.
            if job.state == RunState.CANCELLED:
                return self._receipt(job)
            if result.timed_out:
                job.state = RunState.FAILED
                job.reason = "WALL_CLOCK_TIMEOUT"
            elif result.returncode == PREEMPTED_EXIT_CODE:
                try:
                    if spec.checkpoint_policy is CheckpointPolicy.DISABLED:
                        raise ExperimentError("run does not permit checkpoints")
                    (
                        job.checkpoint_sha256,
                        job.checkpoint_plan_bound,
                    ) = self._bound_checkpoint_sha256(
                        job,
                        allow_legacy_non_evidentiary=True,
                    )
                    job.state = RunState.PREEMPTED
                    job.reason = (
                        "PREEMPTED_WITH_BOUND_CHECKPOINT"
                        if job.checkpoint_plan_bound
                        else "PREEMPTED_WITH_LEGACY_UNBOUND_CHECKPOINT_NON_EVIDENTIARY"
                    )
                except (ValidationError, ExperimentIntegrityError):
                    job.state = RunState.INVALID_OUTPUT
                    job.reason = "PREEMPTED_WITHOUT_VALID_CHECKPOINT"
            elif result.returncode != 0:
                job.state = RunState.FAILED
                job.reason = f"PROCESS_EXIT:{result.returncode}"
            else:
                try:
                    self._revalidate_isolated_launches(job)
                    self._capture_and_validate_manifest(job, first_capture=True)
                    job.state = RunState.SUCCEEDED
                    reason_codes = []
                    if result.stdout_truncated:
                        reason_codes.append("STDOUT_TRUNCATED")
                    if result.stderr_truncated:
                        reason_codes.append("STDERR_TRUNCATED")
                    if spec.evidence_class is EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE:
                        reason_codes.append(
                            "SCIENTIFIC_EVIDENCE_BLOCKED_OS_ISOLATION_UNATTESTED"
                        )
                    if (
                        job.execution_mode
                        is LocalMacExecutionMode.INJECTED_DIAGNOSTIC
                    ):
                        reason_codes.append(
                            "INJECTED_DIAGNOSTIC_UNTESTED_UNPROMOTABLE"
                        )
                    job.reason = ",".join(reason_codes) or None
                except (ValidationError, ExperimentIntegrityError, PathSecurityError) as exc:
                    job.state = RunState.INVALID_OUTPUT
                    job.reason = f"OUTPUT_INVALID:{type(exc).__name__}:{exc}"
        return self._receipt(job)

    def resume(self, job_id: str) -> SubmissionReceipt:
        """Explicitly continue one preempted job from its bound checkpoint."""

        with self._lock:
            job = self._job(job_id)
            if self._terminal_profile(job.spec):
                raise ExperimentError("terminal capture profile forbids resume")
            self._revalidate_isolated_launches(job)
            if job.state is not RunState.PREEMPTED or job.checkpoint_sha256 is None:
                raise ExperimentError("only a checkpointed preempted job may resume")
            checkpoint_sha256, checkpoint_plan_bound = self._bound_checkpoint_sha256(job)
            if not checkpoint_plan_bound:
                raise ExperimentIntegrityError("checkpoint does not bind the execution plan")
            if checkpoint_sha256 != job.checkpoint_sha256:
                raise ExperimentIntegrityError("checkpoint changed before resume")
            job.resumed_from_checkpoint_sha256 = checkpoint_sha256
            job.state = RunState.QUEUED
            job.reason = "EXPLICIT_CHECKPOINT_RESUME_QUEUED"
        acquired = self._execution_slots.acquire(timeout=self._queue_timeout_seconds)
        if not acquired:
            with self._lock:
                job.state = RunState.PREEMPTED
                job.reason = "LOCAL_RESUME_QUEUE_TIMEOUT"
            return self._receipt(job)
        with self._lock:
            if job.state == RunState.CANCELLED:
                self._execution_slots.release()
                return self._receipt(job)
            job.state = RunState.RUNNING
            job.execution_count += 1
            execution_count = job.execution_count
        environment = self._scrubbed_environment(job.spec, job.directory)
        try:
            try:
                if self._execution_mode is LocalMacExecutionMode.BOUND_BUILTIN:
                    self._require_exact_builtin_runner()
                result = self._execution_runner(job.spec, job.directory, environment)
                if not isinstance(result, ExecutionResult):
                    raise ExperimentError("execution runner returned an invalid result")
            except Exception as exc:
                with self._lock:
                    job.state = RunState.FAILED
                    job.reason = f"RESUME_EXCEPTION:{type(exc).__name__}"
                if isinstance(exc, (ExperimentError, ExperimentIntegrityError, PathSecurityError)):
                    raise
                return self._receipt(job)
        finally:
            self._execution_slots.release()
        return self._finalize_execution(
            job,
            result,
            log_suffix=f"-resume-{execution_count}",
        )

    def _capture_and_validate_manifest(self, job: _LocalJob, *, first_capture: bool) -> None:
        payload = read_confined_bytes(
            job.directory,
            "output-manifest.json",
            reject_hardlinks=True,
            max_bytes=MAX_OUTPUT_MANIFEST_BYTES,
        )
        assert payload is not None
        digest = hashlib.sha256(payload).hexdigest()
        if not first_capture and job.manifest_sha256 != digest:
            raise ExperimentIntegrityError("output manifest changed after execution")
        value = safe_json_loads(payload, max_bytes=MAX_OUTPUT_MANIFEST_BYTES)
        manifest = OutputManifest.from_mapping(value)
        spec = job.spec
        if (
            manifest.run_id != spec.run_id
            or manifest.spec_sha256 != spec.sha256
            or manifest.code_sha256 != spec.code_sha256
            or manifest.data_sha256 != spec.data_sha256
            or manifest.configuration_sha256 != spec.configuration_sha256
            or manifest.evaluator_sha256 != spec.evaluator_sha256
        ):
            raise ExperimentIntegrityError("output manifest frozen binding mismatch")
        if manifest.planned_seeds != spec.seeds:
            raise ExperimentIntegrityError("output manifest planned seeds changed")
        reported_seeds = tuple(item.seed for item in manifest.seed_results)
        if len(set(reported_seeds)) != len(reported_seeds) or set(reported_seeds) != set(spec.seeds):
            raise ExperimentIntegrityError("all planned seeds must be reported exactly once")
        artifact_digests: dict[str, OutputArtifact] = {}
        captured: list[tuple[str, str]] = []
        for artifact in manifest.artifacts:
            if artifact.sha256 in artifact_digests:
                raise ExperimentIntegrityError("duplicate output artifact digest")
            data = read_confined_bytes(
                job.directory,
                artifact.path,
                reject_hardlinks=True,
                max_bytes=MAX_OUTPUT_ARTIFACT_BYTES,
            )
            assert data is not None
            actual = hashlib.sha256(data).hexdigest()
            if actual != artifact.sha256 or len(data) != artifact.size:
                raise ExperimentIntegrityError("output artifact hash or size mismatch")
            artifact_digests[artifact.sha256] = artifact
            captured.append((artifact.path, actual))
        for seed_result in manifest.seed_results:
            if seed_result.artifact_sha256 is not None and seed_result.artifact_sha256 not in artifact_digests:
                raise ExperimentIntegrityError("seed result references an unverified artifact")
        ablation_by_id: dict[str, AblationResult] = {}
        for ablation in manifest.ablations:
            if ablation.ablation_id in ablation_by_id:
                raise ExperimentIntegrityError("duplicate ablation result")
            if ablation.artifact_sha256 not in artifact_digests:
                raise ExperimentIntegrityError("ablation references an unverified artifact")
            ablation_by_id[ablation.ablation_id] = ablation
        for required in spec.required_ablations:
            item = ablation_by_id.get(required)
            if item is None:
                raise ExperimentIntegrityError(f"required ablation is missing: {required}")
            if item.status != "PASS":
                raise ExperimentIntegrityError(f"required ablation did not pass: {required}")
        if _missing_expected_output_types(spec, manifest):
            raise ExperimentIntegrityError("output manifest omits a frozen expected output type")
        if not first_capture and tuple(captured) != job.artifact_hashes:
            raise ExperimentIntegrityError("output artifacts changed after execution")
        if first_capture:
            job.manifest = manifest
            job.manifest_sha256 = digest
            job.manifest_bytes = payload
            job.artifact_hashes = tuple(captured)

    def reconcile(self, job_id: str) -> JobStatus:
        with self._lock:
            job = self._job(job_id)
            if self._terminal_profile(job.spec):
                if (
                    job.state in {RunState.SUBMITTED, RunState.QUEUED, RunState.RUNNING}
                    and not job.terminal_finished.is_set()
                ):
                    return self._status(job)
                self.collect_terminal_observation(job_id)
                return self._status(job)
            if job.state == RunState.SUCCEEDED:
                try:
                    self._revalidate_isolated_launches(job)
                    self._capture_and_validate_manifest(job, first_capture=False)
                except (ValidationError, ExperimentIntegrityError, PathSecurityError) as exc:
                    job.state = RunState.INVALID_OUTPUT
                    job.reason = f"STALE_OR_ALTERED_OUTPUT:{type(exc).__name__}:{exc}"
            return self._status(job)

    def cancel(self, job_id: str) -> JobStatus:
        active: _ActiveLocalProcess | None = None
        with self._lock:
            job = self._job(job_id)
            if job.state in {RunState.SUBMITTED, RunState.QUEUED, RunState.RUNNING}:
                job.state = RunState.CANCELLED
                job.reason = "CANCELLED_BY_CALLER"
                active = self._active_processes.get(job.job_id)
                if (
                    self._terminal_profile(job.spec)
                    and job.terminal_invocation_count == 0
                ):
                    self._finish_terminal(job, None)
        if active is not None:
            self._terminate_process_group(active)
        if self._terminal_profile(job.spec):
            if not job.terminal_finished.wait(
                timeout=LOCAL_PROCESS_KILL_GRACE_SECONDS * 3,
            ):
                raise ExperimentIntegrityError(
                    "terminal cancellation capture remains unresolved"
                )
            self.collect_terminal_observation(job_id)
        with self._lock:
            return self._status(job)

    def collect(self, job_id: str) -> CollectedRun:
        with self._lock:
            status = self.reconcile(job_id)
            job = self._job(job_id)
            if status.state != RunState.SUCCEEDED:
                raise ExperimentIntegrityError("only a validated successful run is collectable")
            if (
                job.manifest is None
                or job.manifest_sha256 is None
                or job.manifest_bytes is None
            ):
                raise ExperimentIntegrityError("validated output manifest is absent")
            return CollectedRun(
                backend_id=self.backend_id,
                spec=job.spec,
                manifest=job.manifest,
                manifest_sha256=job.manifest_sha256,
                manifest_bytes=job.manifest_bytes,
                network_used=False,
                scientific_evidence=self._job_is_scientific_evidence(job),
                validation_status=self._job_validation_status(job),
                execution_plan_sha256=(
                    job.execution_plan.sha256
                    if job.execution_plan is not None
                    else None
                ),
                execution_input_binding_sha256=(
                    job.execution_input_binding_sha256
                ),
                returned_artifact_sha256s=tuple(
                    digest for _, digest in job.artifact_hashes
                ),
                network_isolation_attested=False,
            )


@dataclass
class _FakeGPUJob:
    spec: FrozenRunSpec
    idempotency_key: str
    job_id: str
    state: RunState = RunState.QUEUED
    reason: str | None = None
    checkpoint_token: str | None = None
    manifest: OutputManifest | None = None
    queue_sequence: int = 0
    submission_plan_sha256: str | None = None
    staged_artifact_payloads: tuple[StagedArtifact, ...] = ()


class FakeGPUCloudBackend:
    """Deterministic non-evidentiary fixture for remote lifecycle testing."""

    backend_id = "fake-gpu-cloud"
    provider_name = "DETERMINISTIC_FIXTURE_ONLY"
    validation_status = ValidationStatus.UNTESTED
    network_used = False
    network_use_status = NetworkUseStatus.UNKNOWN_UNATTESTED
    scientific_evidence = False
    capabilities = GPUCloudCapabilities(
        cuda=True,
        single_gpu=True,
        multi_gpu=True,
        scheduled_execution=True,
        slurm=True,
        checkpoints=True,
        preemption=True,
        queues=True,
        artifact_return=True,
    )

    def __init__(self) -> None:
        self._jobs: dict[str, _FakeGPUJob] = {}
        self._idempotency: dict[str, tuple[str, str]] = {}
        self._spec_jobs: dict[str, str] = {}
        self._run_specs: dict[str, str] = {}
        self._next_queue_sequence = 0
        self._lock = threading.RLock()

    def _job(self, job_id: str) -> _FakeGPUJob:
        validate_identifier(job_id, "job ID")
        try:
            return self._jobs[job_id]
        except KeyError as exc:
            raise ExperimentError("unknown fake GPU job") from exc

    def _receipt(self, job: _FakeGPUJob) -> SubmissionReceipt:
        return SubmissionReceipt(
            backend_id=self.backend_id,
            job_id=job.job_id,
            idempotency_key=job.idempotency_key,
            spec_sha256=job.spec.sha256,
            state=job.state,
            validation_status=ValidationStatus.UNTESTED,
            network_used=False,
            scientific_evidence=False,
            execution_plan_sha256=job.submission_plan_sha256,
        )

    def _status(self, job: _FakeGPUJob) -> JobStatus:
        checkpoint_sha256 = (
            hashlib.sha256(job.checkpoint_token.encode("utf-8")).hexdigest()
            if job.checkpoint_token is not None
            else None
        )
        return JobStatus(
            backend_id=self.backend_id,
            job_id=job.job_id,
            spec_sha256=job.spec.sha256,
            state=job.state,
            reason=job.reason,
            checkpoint_sha256=checkpoint_sha256,
            network_used=False,
            scientific_evidence=False,
            validation_status=ValidationStatus.UNTESTED,
            execution_plan_sha256=job.submission_plan_sha256,
            queue_position=self.queue_position(job.job_id),
        )

    def queue_position(self, job_id: str) -> int | None:
        with self._lock:
            job = self._job(job_id)
            if job.state is not RunState.QUEUED:
                return None
            queued = [
                value.job_id
                for value in sorted(
                    self._jobs.values(), key=lambda item: item.queue_sequence
                )
                if value.state is RunState.QUEUED
            ]
            return queued.index(job.job_id)

    def submit(self, spec: FrozenRunSpec, *, idempotency_key: str) -> SubmissionReceipt:
        """Compatibility-only lifecycle fixture for non-GPU, non-evidentiary specs.

        GPU_CLOUD work must use :meth:`submit_planned` so the escalation plan
        is attached atomically before the job becomes visible.
        """

        if not isinstance(spec, FrozenRunSpec):
            raise ExperimentError("spec must be FrozenRunSpec")
        if spec.compute_profile.mode is ComputeMode.GPU_CLOUD:
            raise ExperimentError("GPU_CLOUD submission requires a bound escalation plan")
        if spec.evidence_class is not EvidenceClass.NON_EVIDENTIARY:
            raise ExperimentError("unplanned fixture submission must be non-evidentiary")
        return self._submit_job(
            spec,
            idempotency_key=idempotency_key,
            submission_plan_sha256=None,
        )

    def _submit_job(
        self,
        spec: FrozenRunSpec,
        *,
        idempotency_key: str,
        submission_plan_sha256: str | None,
    ) -> SubmissionReceipt:
        validate_identifier(idempotency_key, "idempotency key")
        if submission_plan_sha256 is not None:
            validate_sha256(submission_plan_sha256, "GPU submission plan SHA-256")
        with self._lock:
            previous = self._idempotency.get(idempotency_key)
            if previous is not None:
                prior_sha, job_id = previous
                if prior_sha != spec.sha256:
                    raise SubmissionConflictError("idempotency key names a different remote spec")
                previous_job = self._jobs[job_id]
                if previous_job.submission_plan_sha256 != submission_plan_sha256:
                    raise SubmissionConflictError("GPU submission plan changed for a frozen job")
                return self._receipt(previous_job)
            existing_job = self._spec_jobs.get(spec.sha256)
            if existing_job is not None:
                previous_job = self._jobs[existing_job]
                if previous_job.submission_plan_sha256 != submission_plan_sha256:
                    raise SubmissionConflictError("GPU submission plan changed for a frozen job")
                self._idempotency[idempotency_key] = (spec.sha256, existing_job)
                return self._receipt(previous_job)
            prior_run_spec = self._run_specs.get(spec.run_id)
            if prior_run_spec is not None and prior_run_spec != spec.sha256:
                raise SubmissionConflictError("remote run ID names a different frozen spec")
            job_id = f"fake-gpu-{spec.sha256[:16]}"
            job = _FakeGPUJob(
                spec=spec,
                idempotency_key=idempotency_key,
                job_id=job_id,
                queue_sequence=self._next_queue_sequence,
                submission_plan_sha256=submission_plan_sha256,
            )
            self._next_queue_sequence += 1
            self._jobs[job_id] = job
            self._idempotency[idempotency_key] = (spec.sha256, job_id)
            self._spec_jobs[spec.sha256] = job_id
            self._run_specs[spec.run_id] = spec.sha256
            return self._receipt(job)

    def submit_planned(
        self,
        local_spec: FrozenRunSpec,
        cloud_spec: FrozenRunSpec,
        decision: EscalationDecision,
        *,
        idempotency_key: str,
        submission_plan: GPUCloudSubmissionPlan | None = None,
    ) -> SubmissionReceipt:
        """Exercise the GPU lifecycle only after a bound escalation decision."""

        expected = make_gpu_cloud_submission_plan(local_spec, cloud_spec, decision)
        plan = expected if submission_plan is None else submission_plan
        if not isinstance(plan, GPUCloudSubmissionPlan):
            raise ExperimentError("fake GPU submission plan must be typed")
        if (
            plan.spec_sha256 != expected.spec_sha256
            or plan.project_definition_sha256
            != expected.project_definition_sha256
            or plan.compute_profile_sha256 != expected.compute_profile_sha256
            or plan.escalation_decision_sha256
            != expected.escalation_decision_sha256
            or plan.scheduler is not expected.scheduler
            or plan.queue_name != expected.queue_name
            or plan.accelerator_count != expected.accelerator_count
            or plan.checkpoint_policy is not expected.checkpoint_policy
        ):
            raise ExperimentError(
                "fake GPU submission plan changed its exact scientific or provider binding"
            )
        return self._submit_job(
            cloud_spec,
            idempotency_key=idempotency_key,
            submission_plan_sha256=plan.sha256,
        )

    def reconcile(self, job_id: str) -> JobStatus:
        with self._lock:
            return self._status(self._job(job_id))

    def start(self, job_id: str) -> JobStatus:
        with self._lock:
            job = self._job(job_id)
            if job.state == RunState.QUEUED:
                job.state = RunState.RUNNING
                job.reason = None
            return self._status(job)

    def preempt(self, job_id: str, *, checkpoint_token: str) -> JobStatus:
        _bounded_text(checkpoint_token, "checkpoint token")
        with self._lock:
            job = self._job(job_id)
            if job.state not in {RunState.QUEUED, RunState.RUNNING}:
                raise ExperimentError("only queued or running jobs may be preempted")
            job.state = RunState.PREEMPTED
            job.checkpoint_token = checkpoint_token
            job.reason = "FAKE_PREEMPTION"
            return self._status(job)

    def preemption_checkpoint(self, job_id: str) -> str | None:
        with self._lock:
            job = self._job(job_id)
            return job.checkpoint_token

    def requeue_from_checkpoint(
        self,
        job_id: str,
        *,
        checkpoint_token: str,
    ) -> JobStatus:
        _bounded_text(checkpoint_token, "checkpoint token")
        with self._lock:
            job = self._job(job_id)
            if job.state is not RunState.PREEMPTED:
                raise ExperimentError("only a preempted GPU job may be requeued")
            if job.checkpoint_token != checkpoint_token:
                raise ExperimentIntegrityError("GPU checkpoint token changed before requeue")
            job.state = RunState.QUEUED
            job.queue_sequence = self._next_queue_sequence
            self._next_queue_sequence += 1
            job.reason = "FAKE_CHECKPOINT_REQUEUE_UNTESTED"
            return self._status(job)

    def complete(
        self,
        job_id: str,
        manifest: OutputManifest,
        *,
        returned_payloads: Mapping[str, bytes] | None = None,
    ) -> JobStatus:
        if not isinstance(manifest, OutputManifest):
            raise ExperimentError("fake completion manifest must be typed")
        with self._lock:
            job = self._job(job_id)
            if job.state not in {RunState.QUEUED, RunState.RUNNING}:
                raise ExperimentError("only queued or running jobs may complete")
            _validate_manifest_bindings(job.spec, manifest)
            staged: tuple[StagedArtifact, ...] = ()
            if returned_payloads is None:
                if job.submission_plan_sha256 is not None and manifest.artifacts:
                    raise ExperimentIntegrityError(
                        "planned GPU completion must stage returned artifact bytes"
                    )
            else:
                if not isinstance(returned_payloads, Mapping):
                    raise ExperimentError("returned GPU payloads must be a digest mapping")
                expected_sha256s = {item.sha256 for item in manifest.artifacts}
                if set(returned_payloads) != expected_sha256s:
                    raise ExperimentIntegrityError(
                        "returned GPU payload set differs from the output manifest"
                    )
                staged_items = tuple(
                    StagedArtifact(
                        descriptor=item,
                        payload=returned_payloads[item.sha256],
                    )
                    for item in manifest.artifacts
                )
                if sum(len(item.payload) for item in staged_items) > MAX_RETURNED_ARTIFACT_TOTAL_BYTES:
                    raise ExperimentError("returned GPU artifact bytes exceed the staging bound")
                staged = staged_items
            job.manifest = manifest
            job.staged_artifact_payloads = staged
            job.state = RunState.SUCCEEDED
            job.reason = "FAKE_COMPLETION_NON_EVIDENTIARY"
            return self._status(job)

    def fail(self, job_id: str, reason: str) -> JobStatus:
        _bounded_text(reason, "failure reason")
        with self._lock:
            job = self._job(job_id)
            if job.state not in {RunState.QUEUED, RunState.RUNNING}:
                raise ExperimentError("only queued or running jobs may fail")
            job.state = RunState.FAILED
            job.reason = reason
            return self._status(job)

    def cancel(self, job_id: str) -> JobStatus:
        with self._lock:
            job = self._job(job_id)
            if job.state in {RunState.QUEUED, RunState.RUNNING, RunState.SUBMITTED}:
                job.state = RunState.CANCELLED
                job.reason = "CANCELLED_BY_CALLER"
            return self._status(job)

    def collect(self, job_id: str) -> CollectedRun:
        with self._lock:
            job = self._job(job_id)
            if job.state != RunState.SUCCEEDED or job.manifest is None:
                raise ExperimentIntegrityError("fake GPU job is not collectable")
            manifest_bytes = canonical_json_bytes(job.manifest.to_dict())
            return CollectedRun(
                backend_id=self.backend_id,
                spec=job.spec,
                manifest=job.manifest,
                manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
                manifest_bytes=manifest_bytes,
                network_used=False,
                scientific_evidence=False,
                validation_status=ValidationStatus.UNTESTED,
                execution_plan_sha256=job.submission_plan_sha256,
                returned_artifact_sha256s=self.returned_artifacts(job_id),
            )

    def returned_artifacts(self, job_id: str) -> tuple[str, ...]:
        with self._lock:
            job = self._job(job_id)
            if job.state is not RunState.SUCCEEDED or job.manifest is None:
                raise ExperimentIntegrityError("GPU artifacts are not ready for return")
            if job.staged_artifact_payloads:
                return tuple(item.descriptor.sha256 for item in job.staged_artifact_payloads)
            return tuple(item.sha256 for item in job.manifest.artifacts)

    def staged_artifacts(self, job_id: str) -> tuple[StagedArtifact, ...]:
        with self._lock:
            job = self._job(job_id)
            if job.state is not RunState.SUCCEEDED or job.manifest is None:
                raise ExperimentIntegrityError("GPU artifacts are not staged for return")
            if job.submission_plan_sha256 is not None and (
                len(job.staged_artifact_payloads) != len(job.manifest.artifacts)
            ):
                raise ExperimentIntegrityError("planned GPU artifacts were not fully staged")
            return job.staged_artifact_payloads


def _missing_expected_output_types(
    spec: FrozenRunSpec,
    manifest: OutputManifest,
) -> tuple[str, ...]:
    """Return unsatisfied minimum output types, not semantic or execution authority.

    The manifest itself and its structured seed collection are intrinsic outputs.
    Other types must be declared by artifact descriptors; callers remain
    responsible for exact artifact-byte validation and scientific interpretation.
    Additional declared outputs are permitted by the frozen minimum interface.
    """

    observed = {"output_manifest", *(item.logical_type for item in manifest.artifacts)}
    if manifest.seed_results:
        # Both historical spellings describe the structured per-seed collection.
        observed.update(("seed_result", "seed_results"))
    return tuple(item for item in spec.expected_outputs if item not in observed)


def _validate_manifest_bindings(
    spec: FrozenRunSpec,
    manifest: OutputManifest,
) -> None:
    if (
        manifest.run_id != spec.run_id
        or manifest.spec_sha256 != spec.sha256
        or manifest.code_sha256 != spec.code_sha256
        or manifest.data_sha256 != spec.data_sha256
        or manifest.configuration_sha256 != spec.configuration_sha256
        or manifest.evaluator_sha256 != spec.evaluator_sha256
        or manifest.planned_seeds != spec.seeds
    ):
        raise ExperimentIntegrityError("manifest does not match frozen run spec")
    seeds = tuple(item.seed for item in manifest.seed_results)
    if len(set(seeds)) != len(seeds) or set(seeds) != set(spec.seeds):
        raise ExperimentIntegrityError("all planned seeds must be present exactly once")
    artifacts = {item.sha256 for item in manifest.artifacts}
    if len(artifacts) != len(manifest.artifacts):
        raise ExperimentIntegrityError("manifest has duplicate artifacts")
    for result in manifest.seed_results:
        if result.artifact_sha256 is not None and result.artifact_sha256 not in artifacts:
            raise ExperimentIntegrityError("seed result references absent artifact")
    ablations = {item.ablation_id: item for item in manifest.ablations}
    if len(ablations) != len(manifest.ablations):
        raise ExperimentIntegrityError("manifest has duplicate ablations")
    for required in spec.required_ablations:
        item = ablations.get(required)
        if item is None or item.status != "PASS" or item.artifact_sha256 not in artifacts:
            raise ExperimentIntegrityError("required ablation is missing or non-evidentiary")
    if _missing_expected_output_types(spec, manifest):
        raise ExperimentIntegrityError("manifest omits a frozen expected output type")


def compare_clean_rerun(
    expected: CollectedRun,
    observed: CollectedRun,
    *,
    tolerance: float | None = None,
) -> ReproductionComparison:
    """Compare all seed metrics without widening or selecting favorable seeds."""

    if expected.spec.comparison_tolerance != observed.spec.comparison_tolerance:
        return ReproductionComparison(
            status=ReproductionStatus.IDENTITY_MISMATCH,
            maximum_absolute_difference=None,
            tolerance=expected.spec.comparison_tolerance,
            reason="frozen comparison tolerances differ",
            compared_seeds=(),
        )
    allowed_tolerance = (
        expected.spec.comparison_tolerance
        if tolerance is None
        else _finite_metric(tolerance, "tolerance")
    )
    if allowed_tolerance < 0:
        raise ExperimentError("tolerance must be non-negative")
    if allowed_tolerance != expected.spec.comparison_tolerance:
        raise ExperimentError("comparison tolerance differs from the frozen run spec")
    if expected.spec.scientific_binding_sha256 != observed.spec.scientific_binding_sha256:
        return ReproductionComparison(
            status=ReproductionStatus.IDENTITY_MISMATCH,
            maximum_absolute_difference=None,
            tolerance=allowed_tolerance,
            reason="scientific run bindings differ",
            compared_seeds=(),
        )
    expected_results = {item.seed: item for item in expected.manifest.seed_results}
    observed_results = {item.seed: item for item in observed.manifest.seed_results}
    if set(expected_results) != set(expected.spec.seeds) or set(observed_results) != set(observed.spec.seeds):
        raise ExperimentIntegrityError("clean rerun comparison requires every planned seed")
    differences: list[float] = []
    for seed in expected.spec.seeds:
        left = expected_results[seed]
        right = observed_results[seed]
        if left.status != right.status or left.metric is None or right.metric is None:
            return ReproductionComparison(
                status=ReproductionStatus.OUTSIDE_TOLERANCE,
                maximum_absolute_difference=None,
                tolerance=allowed_tolerance,
                reason=f"seed {seed} status or numeric evidence differs",
                compared_seeds=expected.spec.seeds,
            )
        differences.append(abs(left.metric - right.metric))
    maximum = max(differences, default=0.0)
    # Public dataclass fields are descriptive data, never authority.  No
    # registry-resolved, backend-produced isolation attestation exists yet, so
    # even an in-process mutation of ``scientific_evidence`` must not promote a
    # deterministic comparison to scientific PASS.  A future evidence path
    # must resolve and verify that attestation here before enabling PASS.
    non_evidentiary = True
    if maximum > allowed_tolerance:
        status = ReproductionStatus.OUTSIDE_TOLERANCE
        reason = "one or more seed metrics exceed the frozen tolerance"
    elif non_evidentiary:
        status = ReproductionStatus.NON_EVIDENTIARY
        reason = (
            "all seed metrics are within the frozen tolerance, but one or both "
            "runs are explicitly non-evidentiary"
        )
    else:
        status = ReproductionStatus.PASS
        reason = "all seed metrics are within the frozen tolerance"
    return ReproductionComparison(
        status=status,
        maximum_absolute_difference=maximum,
        tolerance=allowed_tolerance,
        reason=reason,
        compared_seeds=expected.spec.seeds,
    )


def validate_explicit_retry(original: FrozenRunSpec, retry: FrozenRunSpec) -> None:
    """Validate an operator-created retry; this function never submits it."""

    if original.phase == ExperimentPhase.CONFIRMATORY or retry.phase == ExperimentPhase.CONFIRMATORY:
        raise ConfirmatoryPolicyError("confirmatory retry or fallback is prohibited")
    if retry.retry_of_run_id != original.run_id or retry.attempt != original.attempt + 1:
        raise ExperimentError("exploratory retry lineage is invalid")
    if original.scientific_binding_sha256 != retry.scientific_binding_sha256:
        raise ExperimentError("retry changed the frozen scientific binding")


def require_no_backend_fallback(
    spec: FrozenRunSpec,
    *,
    submitted_backend_id: str,
    requested_backend_id: str,
) -> None:
    """Fail closed instead of silently moving a run between backends."""

    _bounded_text(submitted_backend_id, "submitted backend ID")
    _bounded_text(requested_backend_id, "requested backend ID")
    if submitted_backend_id != requested_backend_id:
        if spec.phase == ExperimentPhase.CONFIRMATORY:
            raise ConfirmatoryPolicyError("confirmatory backend fallback is prohibited")
        raise ExperimentError("backend fallback requires a new explicit exploratory run")


def validate_compute_escalation(
    local_spec: FrozenRunSpec,
    cloud_spec: FrozenRunSpec,
    decision: EscalationDecision,
) -> None:
    """Verify that GPU escalation preserves the provider-neutral science."""

    if not isinstance(local_spec, FrozenRunSpec) or not isinstance(cloud_spec, FrozenRunSpec):
        raise ExperimentError("compute escalation requires typed run specs")
    if not isinstance(decision, EscalationDecision):
        raise ExperimentError("compute escalation requires a typed decision")
    if local_spec.compute_profile.mode is not ComputeMode.LOCAL_MAC:
        raise ExperimentError("compute escalation source must be LOCAL_MAC")
    if cloud_spec.compute_profile.mode is not ComputeMode.GPU_CLOUD:
        raise ExperimentError("compute escalation target must be GPU_CLOUD")
    if decision.source_profile_sha256 != local_spec.compute_profile.sha256:
        raise ExperimentError("escalation source profile binding differs")
    if decision.target_profile_sha256 != cloud_spec.compute_profile.sha256:
        raise ExperimentError("escalation target profile binding differs")
    if decision.target_estimate_sha256 != cloud_spec.resource_estimate.sha256:
        raise ExperimentError("escalation resource estimate binding differs")
    if local_spec.project_definition_sha256 != cloud_spec.project_definition_sha256:
        raise ExperimentError("compute escalation changed the scientific project definition")
    estimate = cloud_spec.resource_estimate
    if estimate.gpu_count < 1 or estimate.expected_scientific_value <= 0:
        raise ExperimentError("GPU escalation lacks positive scientific value or GPU need")
    if estimate.expected_uncertainty_reduction <= 0:
        raise ExperimentError("GPU escalation lacks expected uncertainty reduction")
    if estimate.escalation_reason is None:
        raise ExperimentError("GPU resource estimate lacks escalation reason")
    if estimate.monetary_cost is None and cloud_spec.compute_profile.hourly_cost is None:
        raise ExperimentError("GPU escalation lacks an expected monetary cost")
    if cloud_spec.compute_profile.accelerator_count != estimate.gpu_count:
        raise ExperimentError("GPU escalation count differs from its resource estimate")


@dataclass(frozen=True)
class GPUCloudSubmissionPlan:
    spec_sha256: str
    project_definition_sha256: str
    compute_profile_sha256: str
    escalation_decision_sha256: str
    scheduler: SchedulerKind
    queue_name: str | None
    accelerator_count: int
    checkpoint_policy: CheckpointPolicy
    maximum_total_attempts: int = 1
    maximum_cumulative_monetary_cost: float = 0.0
    maximum_cumulative_wall_clock_seconds: float = 86_400.0
    artifact_return_required: bool = True
    external_validation: ValidationStatus = ValidationStatus.UNTESTED

    def __post_init__(self) -> None:
        for value, label in (
            (self.spec_sha256, "GPU submission spec SHA-256"),
            (self.project_definition_sha256, "GPU project definition SHA-256"),
            (self.compute_profile_sha256, "GPU compute profile SHA-256"),
            (self.escalation_decision_sha256, "GPU escalation decision SHA-256"),
        ):
            validate_sha256(value, label)
        for name, enum_type in (
            ("scheduler", SchedulerKind),
            ("checkpoint_policy", CheckpointPolicy),
            ("external_validation", ValidationStatus),
        ):
            value = getattr(self, name)
            if not isinstance(value, enum_type):
                try:
                    object.__setattr__(self, name, enum_type(value))
                except (TypeError, ValueError) as exc:
                    raise ExperimentError(f"unknown GPU submission {name}") from exc
        if self.scheduler is SchedulerKind.LOCAL:
            raise ExperimentError("GPU submission cannot use local scheduling")
        if self.scheduler in {SchedulerKind.SCHEDULED, SchedulerKind.SLURM}:
            _bounded_text(self.queue_name, "GPU submission queue", 256)
        if (
            isinstance(self.accelerator_count, bool)
            or not isinstance(self.accelerator_count, int)
            or not 1 <= self.accelerator_count <= 64
        ):
            raise ExperimentError("GPU submission accelerator count is invalid")
        if self.checkpoint_policy is CheckpointPolicy.DISABLED:
            raise ExperimentError("GPU submissions require checkpoints")
        if (
            isinstance(self.maximum_total_attempts, bool)
            or not isinstance(self.maximum_total_attempts, int)
            or not 1 <= self.maximum_total_attempts <= 64
        ):
            raise ExperimentError("GPU submission attempt ceiling is invalid")
        for name in (
            "maximum_cumulative_monetary_cost",
            "maximum_cumulative_wall_clock_seconds",
        ):
            value = _finite_metric(getattr(self, name), name.replace("_", " "))
            if value < 0 or (
                name == "maximum_cumulative_wall_clock_seconds" and value == 0
            ):
                raise ExperimentError("GPU submission cumulative ceiling is invalid")
            object.__setattr__(self, name, value)
        if self.artifact_return_required is not True:
            raise ExperimentError("GPU submission must return artifacts")
        if self.external_validation is not ValidationStatus.UNTESTED:
            raise ExperimentError("GPU submission remains externally UNTESTED")

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec_sha256": self.spec_sha256,
            "project_definition_sha256": self.project_definition_sha256,
            "compute_profile_sha256": self.compute_profile_sha256,
            "escalation_decision_sha256": self.escalation_decision_sha256,
            "scheduler": self.scheduler.value,
            "queue_name": self.queue_name,
            "accelerator_count": self.accelerator_count,
            "checkpoint_policy": self.checkpoint_policy.value,
            "maximum_total_attempts": self.maximum_total_attempts,
            "maximum_cumulative_monetary_cost": (
                self.maximum_cumulative_monetary_cost
            ),
            "maximum_cumulative_wall_clock_seconds": (
                self.maximum_cumulative_wall_clock_seconds
            ),
            "artifact_return_required": True,
            "external_validation": self.external_validation.value,
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_dict())).hexdigest()


def make_gpu_cloud_submission_plan(
    local_spec: FrozenRunSpec,
    cloud_spec: FrozenRunSpec,
    decision: EscalationDecision,
    budget: ComputeEscalationBudget | None = None,
) -> GPUCloudSubmissionPlan:
    validate_compute_escalation(local_spec, cloud_spec, decision)
    profile = cloud_spec.compute_profile
    expected_cost = _compute_escalation_target_cost(cloud_spec)
    maximum_total_attempts = budget.maximum_total_attempts if budget else 1
    cumulative_monetary = (
        budget.maximum_cumulative_monetary_cost if budget else expected_cost
    )
    cumulative_wall = (
        budget.maximum_cumulative_wall_clock_seconds
        if budget
        else cloud_spec.resource_estimate.wall_clock_seconds
    )
    assert cumulative_monetary is not None
    return GPUCloudSubmissionPlan(
        spec_sha256=cloud_spec.sha256,
        project_definition_sha256=cloud_spec.project_definition_sha256,
        compute_profile_sha256=profile.sha256,
        escalation_decision_sha256=decision.sha256,
        scheduler=profile.scheduler,
        queue_name=profile.queue_name,
        accelerator_count=profile.accelerator_count,
        checkpoint_policy=cloud_spec.checkpoint_policy,
        maximum_total_attempts=maximum_total_attempts,
        maximum_cumulative_monetary_cost=cumulative_monetary,
        maximum_cumulative_wall_clock_seconds=cumulative_wall,
    )


@dataclass(frozen=True)
class ComputeEscalationPlanAuthority:
    """Registry-and-ledger authority for a GPU *plan*, never its execution."""

    authority_id: str
    run_id: str
    ledger_path: str
    object_id: str
    local_spec_artifact_sha256: str
    cloud_spec_artifact_sha256: str
    source_profile_artifact_sha256: str
    target_profile_artifact_sha256: str
    target_estimate_artifact_sha256: str
    human_gate_policy_artifact_sha256: str
    budget_artifact_sha256: str
    decision_artifact_sha256: str
    submission_plan_artifact_sha256: str
    input_artifact_record_hashes: tuple[str, ...]
    local_spec_sha256: str
    cloud_spec_sha256: str
    project_definition_sha256: str
    source_profile_sha256: str
    target_profile_sha256: str
    target_estimate_sha256: str
    human_gate_policy_sha256: str
    budget_sha256: str
    decision_sha256: str
    submission_plan_sha256: str
    authority_key_sha256: str
    expected_monetary_cost: float
    maximum_monetary_cost: float
    expected_wall_clock_seconds: float
    maximum_total_attempts: int
    maximum_cumulative_monetary_cost: float
    maximum_cumulative_wall_clock_seconds: float
    ledger_event_id: str
    ledger_event_hash: str
    ledger_event_index: int
    ledger_prefix_head_hash: str
    authority_scope: str = "PLAN_PROTOCOL_AUTHORITY_ONLY"
    external_validation: ValidationStatus = ValidationStatus.UNTESTED
    live_gpu_availability_verified: bool = False
    gpu_execution_validated: bool = False

    def __post_init__(self) -> None:
        for name in ("authority_id", "run_id", "object_id", "ledger_event_id"):
            validate_identifier(getattr(self, name), name.replace("_", " "))
        object.__setattr__(
            self,
            "ledger_path",
            _relative_path(self.ledger_path, "compute escalation ledger path"),
        )
        for name in (
            "local_spec_artifact_sha256",
            "cloud_spec_artifact_sha256",
            "source_profile_artifact_sha256",
            "target_profile_artifact_sha256",
            "target_estimate_artifact_sha256",
            "human_gate_policy_artifact_sha256",
            "budget_artifact_sha256",
            "decision_artifact_sha256",
            "submission_plan_artifact_sha256",
            "local_spec_sha256",
            "cloud_spec_sha256",
            "project_definition_sha256",
            "source_profile_sha256",
            "target_profile_sha256",
            "target_estimate_sha256",
            "human_gate_policy_sha256",
            "budget_sha256",
            "decision_sha256",
            "submission_plan_sha256",
            "authority_key_sha256",
            "ledger_event_hash",
            "ledger_prefix_head_hash",
        ):
            validate_sha256(getattr(self, name), name.replace("_", " "))
        if (
            not isinstance(self.input_artifact_record_hashes, tuple)
            or len(self.input_artifact_record_hashes)
            != len(self.input_artifact_hashes)
            or len(set(self.input_artifact_record_hashes))
            != len(self.input_artifact_record_hashes)
        ):
            raise ExperimentError(
                "compute escalation input metadata hashes are incomplete"
            )
        for value in self.input_artifact_record_hashes:
            validate_sha256(value, "compute escalation input record SHA-256")
        for name in (
            "expected_monetary_cost",
            "maximum_monetary_cost",
            "expected_wall_clock_seconds",
            "maximum_cumulative_monetary_cost",
            "maximum_cumulative_wall_clock_seconds",
        ):
            value = _finite_metric(getattr(self, name), name.replace("_", " "))
            if value < 0:
                raise ExperimentError(
                    "compute escalation monetary bounds must be non-negative"
                )
            object.__setattr__(self, name, value)
        if self.expected_monetary_cost > self.maximum_monetary_cost:
            raise ExperimentError("compute escalation exceeds its frozen budget")
        if (
            isinstance(self.maximum_total_attempts, bool)
            or not isinstance(self.maximum_total_attempts, int)
            or not 1 <= self.maximum_total_attempts <= 64
            or self.expected_monetary_cost * self.maximum_total_attempts
            > self.maximum_cumulative_monetary_cost
            or self.expected_wall_clock_seconds * self.maximum_total_attempts
            > self.maximum_cumulative_wall_clock_seconds
        ):
            raise ExperimentError(
                "compute escalation authority exceeds cumulative attempt budget"
            )
        if (
            isinstance(self.ledger_event_index, bool)
            or not isinstance(self.ledger_event_index, int)
            or self.ledger_event_index < 0
        ):
            raise ExperimentError("compute escalation event index is invalid")
        if not isinstance(self.external_validation, ValidationStatus):
            try:
                object.__setattr__(
                    self,
                    "external_validation",
                    ValidationStatus(self.external_validation),
                )
            except (TypeError, ValueError) as exc:
                raise ExperimentError(
                    "compute escalation external-validation status is invalid"
                ) from exc
        if (
            self.authority_scope != "PLAN_PROTOCOL_AUTHORITY_ONLY"
            or self.external_validation is not ValidationStatus.UNTESTED
            or self.live_gpu_availability_verified is not False
            or self.gpu_execution_validated is not False
            or self.ledger_prefix_head_hash != self.ledger_event_hash
        ):
            raise ExperimentError(
                "compute escalation plan authority exceeds its scientific scope"
            )

    @property
    def input_artifact_hashes(self) -> tuple[str, ...]:
        return (
            self.local_spec_artifact_sha256,
            self.cloud_spec_artifact_sha256,
            self.source_profile_artifact_sha256,
            self.target_profile_artifact_sha256,
            self.target_estimate_artifact_sha256,
            self.human_gate_policy_artifact_sha256,
            self.budget_artifact_sha256,
            self.decision_artifact_sha256,
            self.submission_plan_artifact_sha256,
        )

    @property
    def scientific_gate_passed(self) -> bool:
        """The prospective plan is valid; cloud science is still UNTESTED."""

        return (
            self.authority_scope == "PLAN_PROTOCOL_AUTHORITY_ONLY"
            and self.external_validation is ValidationStatus.UNTESTED
            and self.live_gpu_availability_verified is False
            and self.gpu_execution_validated is False
            and self.expected_monetary_cost <= self.maximum_monetary_cost
            and self.expected_monetary_cost * self.maximum_total_attempts
            <= self.maximum_cumulative_monetary_cost
            and self.expected_wall_clock_seconds * self.maximum_total_attempts
            <= self.maximum_cumulative_wall_clock_seconds
        )

    def to_dict(self) -> dict[str, Any]:
        result = {name: getattr(self, name) for name in self.__dataclass_fields__}
        result["schema_version"] = COMPUTE_ESCALATION_PLAN_AUTHORITY_SCHEMA
        result["input_artifact_record_hashes"] = list(
            self.input_artifact_record_hashes
        )
        result["external_validation"] = self.external_validation.value
        return result

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
    ) -> "ComputeEscalationPlanAuthority":
        expected = set(cls.__dataclass_fields__) | {"schema_version"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ExperimentError("compute escalation authority schema is invalid")
        if value["schema_version"] != COMPUTE_ESCALATION_PLAN_AUTHORITY_SCHEMA:
            raise ExperimentError("unsupported compute escalation authority schema")
        try:
            arguments = {name: value[name] for name in cls.__dataclass_fields__}
            arguments["input_artifact_record_hashes"] = tuple(
                arguments["input_artifact_record_hashes"]
            )
            arguments["external_validation"] = ValidationStatus(
                arguments["external_validation"]
            )
            return cls(**arguments)
        except (KeyError, TypeError, ValueError) as exc:
            raise ExperimentError("compute escalation authority is malformed") from exc


def _parse_compute_profile(value: Mapping[str, Any]) -> ComputeProfile:
    expected = {
        "profile_id",
        "mode",
        "accelerator",
        "scheduler",
        "experiment_class",
        "cpu_cores",
        "accelerator_count",
        "memory_limit_bytes",
        "accelerator_memory_limit_bytes",
        "disk_limit_bytes",
        "maximum_concurrency",
        "minimum_batch_size",
        "preferred_batch_size",
        "maximum_batch_size",
        "maximum_memory_fraction",
        "supports_checkpointing",
        "supports_preemption",
        "validation_status",
        "validation_artifact_sha256",
        "queue_name",
        "multi_accelerator_rationale",
        "hourly_cost",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ExperimentError("compute profile artifact schema is invalid")
    try:
        profile = ComputeProfile(**dict(value))
    except (TypeError, ValueError) as exc:
        raise ExperimentError("compute profile artifact is malformed") from exc
    if profile.to_dict() != dict(value):
        raise ExperimentError("compute profile artifact is non-canonical")
    return profile


def _parse_resource_estimate(value: Mapping[str, Any]) -> ResourceEstimate:
    expected = {
        "expected_scientific_value",
        "expected_uncertainty_reduction",
        "cpu_cores",
        "gpu_count",
        "ram_bytes",
        "vram_bytes",
        "disk_bytes",
        "wall_clock_seconds",
        "monetary_cost",
        "escalation_reason",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ExperimentError("resource estimate artifact schema is invalid")
    try:
        estimate = ResourceEstimate(**dict(value))
    except (TypeError, ValueError) as exc:
        raise ExperimentError("resource estimate artifact is malformed") from exc
    if estimate.to_dict() != dict(value):
        raise ExperimentError("resource estimate artifact is non-canonical")
    return estimate


def _parse_frozen_run_spec(value: Mapping[str, Any]) -> FrozenRunSpec:
    expected = {
        "schema_version",
        "run_id",
        "experiment_id",
        "hypothesis_id",
        "phase",
        "argv",
        "working_directory",
        "code_sha256",
        "data_sha256",
        "configuration_sha256",
        "evaluator_sha256",
        "seeds",
        "comparison_tolerance",
        "timeout_seconds",
        "maximum_stdout_bytes",
        "maximum_stderr_bytes",
        "required_ablations",
        "attempt",
        "retry_of_run_id",
        "network_allowed",
        "shell_allowed",
        "evidence_class",
        "scientific_purpose",
        "expected_outputs",
        "seed_policy",
        "termination_conditions",
        "compute_profile",
        "resource_estimate",
        "cache_policy",
        "checkpoint_policy",
        "bytes_per_sample",
        "worker_overhead_bytes",
        "metadata",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ExperimentError("frozen run-spec artifact schema is invalid")
    if value["schema_version"] != "SCIENTIST_ONE_FROZEN_RUN_SPEC_V1":
        raise ExperimentError("unsupported frozen run-spec artifact schema")
    try:
        arguments = {name: value[name] for name in expected - {"schema_version"}}
        arguments["phase"] = ExperimentPhase(arguments["phase"])
        arguments["argv"] = tuple(arguments["argv"])
        arguments["seeds"] = tuple(arguments["seeds"])
        arguments["required_ablations"] = tuple(arguments["required_ablations"])
        arguments["evidence_class"] = EvidenceClass(arguments["evidence_class"])
        arguments["expected_outputs"] = tuple(arguments["expected_outputs"])
        arguments["termination_conditions"] = tuple(
            arguments["termination_conditions"]
        )
        arguments["compute_profile"] = _parse_compute_profile(
            arguments["compute_profile"]
        )
        arguments["resource_estimate"] = _parse_resource_estimate(
            arguments["resource_estimate"]
        )
        arguments["cache_policy"] = CachePolicy(arguments["cache_policy"])
        arguments["checkpoint_policy"] = CheckpointPolicy(
            arguments["checkpoint_policy"]
        )
        spec = FrozenRunSpec(**arguments)
    except (KeyError, TypeError, ValueError) as exc:
        raise ExperimentError("frozen run-spec artifact is malformed") from exc
    if spec.to_dict() != dict(value):
        raise ExperimentError("frozen run-spec artifact is non-canonical")
    return spec


def _parse_escalation_decision(value: Mapping[str, Any]) -> EscalationDecision:
    expected = {
        "decision_id",
        "source_profile_sha256",
        "target_profile_sha256",
        "target_estimate_sha256",
        "rationale",
        "scientific_equivalence_rationale",
        "expected_information_gain",
        "lower_cost_alternatives_exhausted",
        "external_validation",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ExperimentError("escalation decision artifact schema is invalid")
    try:
        arguments = dict(value)
        arguments["external_validation"] = ValidationStatus(
            arguments["external_validation"]
        )
        decision = EscalationDecision(**arguments)
    except (TypeError, ValueError) as exc:
        raise ExperimentError("escalation decision artifact is malformed") from exc
    if decision.to_dict() != dict(value):
        raise ExperimentError("escalation decision artifact is non-canonical")
    return decision


def _parse_submission_plan(value: Mapping[str, Any]) -> GPUCloudSubmissionPlan:
    expected = {
        "spec_sha256",
        "project_definition_sha256",
        "compute_profile_sha256",
        "escalation_decision_sha256",
        "scheduler",
        "queue_name",
        "accelerator_count",
        "checkpoint_policy",
        "maximum_total_attempts",
        "maximum_cumulative_monetary_cost",
        "maximum_cumulative_wall_clock_seconds",
        "artifact_return_required",
        "external_validation",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ExperimentError("GPU submission-plan artifact schema is invalid")
    try:
        plan = GPUCloudSubmissionPlan(**dict(value))
    except (TypeError, ValueError) as exc:
        raise ExperimentError("GPU submission-plan artifact is malformed") from exc
    if plan.to_dict() != dict(value):
        raise ExperimentError("GPU submission-plan artifact is non-canonical")
    return plan


def _parse_escalation_budget(value: Mapping[str, Any]) -> ComputeEscalationBudget:
    expected = {
        "budget_id",
        "target_profile_sha256",
        "target_estimate_sha256",
        "maximum_monetary_cost",
        "maximum_total_attempts",
        "maximum_cumulative_monetary_cost",
        "maximum_cumulative_wall_clock_seconds",
        "currency",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ExperimentError("compute escalation budget artifact schema is invalid")
    try:
        budget = ComputeEscalationBudget(**dict(value))
    except (TypeError, ValueError) as exc:
        raise ExperimentError("compute escalation budget artifact is malformed") from exc
    if budget.to_dict() != dict(value):
        raise ExperimentError("compute escalation budget artifact is non-canonical")
    return budget


def _human_gate_policy_value(policy: Any) -> dict[str, Any]:
    from .gates import HumanGatePolicy

    if type(policy) is not HumanGatePolicy:
        raise ExperimentError("compute escalation requires an exact human-gate policy")
    return {
        "profile": policy.profile.value,
        "selective_gates": [gate.value for gate in policy.selective_gates],
    }


def _parse_human_gate_policy(value: Mapping[str, Any]) -> Any:
    from .gates import HumanGate, HumanGatePolicy, HumanGateProfile

    if (
        not isinstance(value, Mapping)
        or set(value) != {"profile", "selective_gates"}
        or not isinstance(value.get("selective_gates"), list)
    ):
        raise ExperimentError("compute escalation human-gate policy is malformed")
    try:
        policy = HumanGatePolicy(
            HumanGateProfile(value["profile"]),
            tuple(HumanGate(item) for item in value["selective_gates"]),
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise ExperimentError(
            "compute escalation human-gate policy cannot be parsed"
        ) from exc
    if _human_gate_policy_value(policy) != dict(value):
        raise ExperimentError("compute escalation human-gate policy is non-canonical")
    return policy


def _compute_escalation_authority_key(
    *,
    run_id: str,
    object_id: str,
    cloud_spec_sha256: str,
    submission_plan_sha256: str,
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "run_id": run_id,
                "object_id": object_id,
                "cloud_spec_sha256": cloud_spec_sha256,
                "submission_plan_sha256": submission_plan_sha256,
            }
        )
    ).hexdigest()


def _preflight_compute_escalation_authority_collision(
    events: tuple[LedgerEvent, ...],
    *,
    authority_key_sha256: str,
    local_spec_sha256: str,
    decision_sha256: str,
    human_gate_policy_sha256: str,
    budget_sha256: str,
) -> None:
    """Reject a competing stable-plan closure before creating artifacts."""

    candidates: list[Mapping[str, Any]] = []
    for event in events:
        binding = thaw_json(event.metadata).get(
            "compute_escalation_plan_authority"
        )
        if (
            isinstance(binding, Mapping)
            and binding.get("schema_version") == COMPUTE_ESCALATION_EVENT_SCHEMA
            and binding.get("authority_key_sha256") == authority_key_sha256
        ):
            candidates.append(binding)
    if len(candidates) > 1:
        raise ExperimentError(
            "competing compute escalation authorities name the same stable plan"
        )
    if candidates:
        candidate = candidates[0]
        if (
            candidate.get("local_spec_sha256") != local_spec_sha256
            or candidate.get("decision_sha256") != decision_sha256
            or candidate.get("human_gate_policy_sha256")
            != human_gate_policy_sha256
            or candidate.get("budget_sha256") != budget_sha256
        ):
            raise ExperimentError(
                "competing compute escalation authority names the same stable plan"
            )


def _compute_escalation_target_cost(cloud_spec: FrozenRunSpec) -> float:
    estimate = cloud_spec.resource_estimate
    if estimate.monetary_cost is not None:
        return estimate.monetary_cost
    hourly = cloud_spec.compute_profile.hourly_cost
    if hourly is None:
        raise ExperimentError("compute escalation target cost is absent")
    return hourly * estimate.wall_clock_seconds / 3600.0


def _validate_compute_escalation_plan_inputs(
    local_spec: FrozenRunSpec,
    cloud_spec: FrozenRunSpec,
    decision: EscalationDecision,
    submission_plan: GPUCloudSubmissionPlan,
    budget: ComputeEscalationBudget,
) -> float:
    validate_compute_escalation(local_spec, cloud_spec, decision)
    expected_plan = make_gpu_cloud_submission_plan(
        local_spec,
        cloud_spec,
        decision,
        budget,
    )
    if submission_plan != expected_plan:
        raise ExperimentError(
            "GPU submission plan differs from fresh compute-escalation derivation"
        )
    if (
        budget.target_profile_sha256 != cloud_spec.compute_profile.sha256
        or budget.target_estimate_sha256 != cloud_spec.resource_estimate.sha256
    ):
        raise ExperimentError(
            "compute escalation budget is bound to another profile or estimate"
        )
    if (
        cloud_spec.resource_estimate.expected_scientific_value
        <= local_spec.resource_estimate.expected_scientific_value
        or cloud_spec.resource_estimate.expected_uncertainty_reduction
        <= local_spec.resource_estimate.expected_uncertainty_reduction
        or decision.expected_information_gain
        != cloud_spec.resource_estimate.expected_uncertainty_reduction
    ):
        raise ExperimentError(
            "compute escalation information value is not derived from its estimates"
        )
    # Keep the exact scientific protocol comparison explicit in addition to
    # FrozenRunSpec.project_definition_sha256 so future execution-only fields
    # cannot silently broaden this boundary.
    if (
        local_spec.experiment_id != cloud_spec.experiment_id
        or local_spec.hypothesis_id != cloud_spec.hypothesis_id
        or local_spec.phase is not cloud_spec.phase
        or local_spec.code_sha256 != cloud_spec.code_sha256
        or local_spec.data_sha256 != cloud_spec.data_sha256
        or local_spec.configuration_sha256 != cloud_spec.configuration_sha256
        or local_spec.evaluator_sha256 != cloud_spec.evaluator_sha256
        or local_spec.seeds != cloud_spec.seeds
        or local_spec.required_ablations != cloud_spec.required_ablations
        or local_spec.scientific_purpose != cloud_spec.scientific_purpose
        or local_spec.expected_outputs != cloud_spec.expected_outputs
        or local_spec.seed_policy != cloud_spec.seed_policy
        or local_spec.termination_conditions != cloud_spec.termination_conditions
    ):
        raise ExperimentError(
            "compute escalation changed exact project, data, evaluator, seeds, or protocol"
        )
    expected_cost = _compute_escalation_target_cost(cloud_spec)
    if expected_cost > budget.maximum_monetary_cost:
        raise ExperimentError("compute escalation exceeds its frozen monetary budget")
    assert budget.maximum_cumulative_monetary_cost is not None
    if (
        expected_cost * budget.maximum_total_attempts
        > budget.maximum_cumulative_monetary_cost
        or cloud_spec.resource_estimate.wall_clock_seconds
        * budget.maximum_total_attempts
        > budget.maximum_cumulative_wall_clock_seconds
    ):
        raise ExperimentError(
            "compute escalation attempt ceiling exceeds cumulative budget"
        )
    return expected_cost


def _registered_gpu_execution_exists(
    registry: ArtifactRegistry,
    *,
    cloud_spec: FrozenRunSpec,
    submission_plan: GPUCloudSubmissionPlan,
) -> bool:
    """Detect already-registered execution before creating plan authority."""

    execution_types = {
        "gpu_cloud_output_manifest",
        "gpu_cloud_return_receipt",
        "gpu_cloud_returned_artifact",
        "gpu_cloud_submission_receipt",
    }
    for record in registry.list_records():
        if (
            record.logical_type == "gpu_cloud_target_run_spec"
            and record.sha256 == cloud_spec.sha256
        ) or (
            record.logical_type == "gpu_cloud_submission_plan"
            and record.sha256 == submission_plan.sha256
        ):
            return True
        if record.logical_type not in execution_types:
            continue
        if (
            cloud_spec.sha256 in record.parent_artifacts
            or submission_plan.sha256 in record.parent_artifacts
        ):
            return True
        if record.mime_type != "application/json":
            continue
        try:
            value = safe_json_loads(registry.get_bytes(record.sha256))
        except ValidationError as exc:
            raise ExperimentError(
                "registered GPU execution artifact cannot be reopened"
            ) from exc
        if isinstance(value, Mapping) and (
            value.get("target_spec_sha256") == cloud_spec.sha256
            or value.get("spec_sha256") == cloud_spec.sha256
            or value.get("submission_plan_sha256") == submission_plan.sha256
        ):
            return True
    return False


def _put_compute_escalation_input(
    registry: ArtifactRegistry,
    *,
    run_id: str,
    logical_type: str,
    creator_role: Role,
    value: Mapping[str, Any],
    parents: tuple[str, ...] = (),
) -> ArtifactRecord:
    return registry.put_json(
        {
            "schema_version": COMPUTE_ESCALATION_INPUT_SCHEMA,
            "run_id": run_id,
            "kind": logical_type,
            "value": dict(value),
        },
        logical_type=logical_type,
        origin=_COMPUTE_ESCALATION_INPUT_ORIGIN,
        creator_role=creator_role,
        creation_command=_COMPUTE_ESCALATION_COMMAND,
        parent_artifacts=parents,
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )


def _load_compute_escalation_input(
    registry: ArtifactRegistry,
    digest: str,
    *,
    run_id: str,
    logical_type: str,
    creator_role: Role,
) -> tuple[ArtifactRecord, Mapping[str, Any]]:
    validate_sha256(digest, "compute escalation input SHA-256")
    try:
        registry.verify(digest, raise_on_error=True)
        record = registry.get_metadata(digest)
        raw = registry.get_bytes(digest)
        wrapper = safe_json_loads(raw)
    except (ArtifactError, ValidationError) as exc:
        raise ExperimentError("compute escalation input cannot be reopened") from exc
    if (
        record.logical_type != logical_type
        or record.creator_role is not creator_role
        or record.origin != _COMPUTE_ESCALATION_INPUT_ORIGIN
        or record.creation_command != _COMPUTE_ESCALATION_COMMAND
        or record.schema_version != "1.0"
        or record.mime_type != "application/json"
        or record.validation_result != "PASS"
        or not record.frozen
        or not isinstance(wrapper, Mapping)
        or set(wrapper) != {"schema_version", "run_id", "kind", "value"}
        or wrapper.get("schema_version") != COMPUTE_ESCALATION_INPUT_SCHEMA
        or wrapper.get("run_id") != run_id
        or wrapper.get("kind") != logical_type
        or not isinstance(wrapper.get("value"), Mapping)
        or raw != canonical_json_bytes(wrapper) + b"\n"
    ):
        raise ExperimentError(
            "compute escalation input metadata or payload is not authoritative"
        )
    return record, wrapper["value"]


def _require_compute_escalation_runtime(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    run_id: str,
) -> tuple[LedgerEvent, ...]:
    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise ExperimentError(
            "compute escalation requires the exact ArtifactRegistry and EventLedger"
        )
    validate_identifier(run_id, "compute escalation run ID")
    if (
        registry.policy.root != ledger.policy.root
        or registry.base_path.name != "registry"
        or ledger.relative_path.name != "events.jsonl"
        or registry.base_path.parent != ledger.relative_path.parent
    ):
        raise ExperimentError(
            "compute escalation requires the canonical paired run registry and ledger"
        )
    try:
        registry.verify_all(raise_on_error=True)
        events = ledger.events()
    except Exception as exc:
        raise ExperimentError(
            "compute escalation registry or ledger cannot be verified"
        ) from exc
    if events and any(event.run_id != run_id for event in events):
        raise ExperimentError("compute escalation ledger names another run")
    return events


def _compute_escalation_event_binding(
    authority_id: str,
    object_id: str,
    input_records: tuple[ArtifactRecord, ...],
    *,
    run_id: str,
    local_spec: FrozenRunSpec,
    cloud_spec: FrozenRunSpec,
    decision: EscalationDecision,
    submission_plan: GPUCloudSubmissionPlan,
    human_gate_policy: Any,
    budget: ComputeEscalationBudget,
) -> dict[str, Any]:
    authority_key_sha256 = _compute_escalation_authority_key(
        run_id=run_id,
        object_id=object_id,
        cloud_spec_sha256=cloud_spec.sha256,
        submission_plan_sha256=submission_plan.sha256,
    )
    return {
        "schema_version": COMPUTE_ESCALATION_EVENT_SCHEMA,
        "authority_id": authority_id,
        "authority_key_sha256": authority_key_sha256,
        "object_id": object_id,
        "input_artifact_hashes": [record.sha256 for record in input_records],
        "input_artifact_record_hashes": [
            str(record.record_hash) for record in input_records
        ],
        "local_spec_sha256": local_spec.sha256,
        "cloud_spec_sha256": cloud_spec.sha256,
        "project_definition_sha256": cloud_spec.project_definition_sha256,
        "decision_sha256": decision.sha256,
        "submission_plan_sha256": submission_plan.sha256,
        "human_gate_policy_artifact_sha256": input_records[5].sha256,
        "human_gate_policy_sha256": hashlib.sha256(
            canonical_json_bytes(_human_gate_policy_value(human_gate_policy))
        ).hexdigest(),
        "budget_sha256": budget.sha256,
        "maximum_total_attempts": budget.maximum_total_attempts,
        "maximum_cumulative_monetary_cost": (
            budget.maximum_cumulative_monetary_cost
        ),
        "maximum_cumulative_wall_clock_seconds": (
            budget.maximum_cumulative_wall_clock_seconds
        ),
        "external_validation": ValidationStatus.UNTESTED.value,
        "authority_scope": "PLAN_PROTOCOL_AUTHORITY_ONLY",
    }


def _require_or_record_compute_escalation_event(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    authority_id: str,
    object_id: str,
    input_records: tuple[ArtifactRecord, ...],
    local_spec: FrozenRunSpec,
    cloud_spec: FrozenRunSpec,
    decision: EscalationDecision,
    submission_plan: GPUCloudSubmissionPlan,
    human_gate_policy: Any,
    budget: ComputeEscalationBudget,
    create: bool,
) -> tuple[LedgerEvent, int]:
    events = _require_compute_escalation_runtime(registry, ledger, run_id)
    binding = _compute_escalation_event_binding(
        authority_id,
        object_id,
        input_records,
        run_id=run_id,
        local_spec=local_spec,
        cloud_spec=cloud_spec,
        decision=decision,
        submission_plan=submission_plan,
        human_gate_policy=human_gate_policy,
        budget=budget,
    )
    candidates: list[tuple[int, LedgerEvent]] = []
    for index, event in enumerate(events):
        metadata = thaw_json(event.metadata)
        event_binding = metadata.get("compute_escalation_plan_authority")
        if (
            isinstance(event_binding, Mapping)
            and event_binding.get("schema_version")
            == COMPUTE_ESCALATION_EVENT_SCHEMA
            and event_binding.get("object_id") == object_id
            and event_binding.get("cloud_spec_sha256") == cloud_spec.sha256
            and event_binding.get("submission_plan_sha256")
            == submission_plan.sha256
        ):
            if dict(event_binding) != binding:
                raise ExperimentError(
                    "competing compute escalation authority names the same stable plan"
                )
            candidates.append((index, event))
    if create and _registered_gpu_execution_exists(
        registry,
        cloud_spec=cloud_spec,
        submission_plan=submission_plan,
    ):
        # Registration is strictly prospective.  Even a matching prewritten
        # checkpoint cannot turn a post-submission call into plan authority;
        # existing authorities remain readable through the require API.
        raise ExperimentError(
            "compute escalation plan authority cannot be created after GPU execution"
        )
    if not candidates and create:
        current_state = events[-1].state_after if events else MacroState.PREFLIGHT
        prior_event_hash = events[-1].event_hash if events else None
        event = ledger.append(LedgerEvent.create(
            run_id=run_id,
            actor_role=Role.PROTOCOL_DESIGNER,
            state_before=current_state,
            requested_state_after=current_state,
            artifact_hashes=tuple(record.sha256 for record in input_records),
            code_version=f"sha256:{cloud_spec.code_sha256}",
            configuration_hash=cloud_spec.configuration_sha256,
            dataset_identifiers=(cloud_spec.data_sha256,),
            random_seeds=cloud_spec.seeds,
            evaluator_outputs=(),
            reason=(
                "verified exact compute-escalation project equivalence, plan, "
                "and budget before GPU submission"
            ),
            event_type="CHECKPOINT",
            metadata={"compute_escalation_plan_authority": binding},
            prior_event_hash=prior_event_hash,
        ))
        candidates.append((len(events), event))
        events = (*events, event)
    if len(candidates) != 1:
        raise ExperimentError(
            "compute escalation requires one exact live plan-authority checkpoint"
        )
    index, event = candidates[0]
    if event.event_hash is None:
        raise ExperimentError("compute escalation event hash is absent")
    if (
        event.actor_role is not Role.PROTOCOL_DESIGNER
        or event.event_type != "CHECKPOINT"
        or event.state_before != event.state_after
        or event.artifact_hashes
        != tuple(record.sha256 for record in input_records)
        or event.code_version != f"sha256:{cloud_spec.code_sha256}"
        or event.configuration_hash != cloud_spec.configuration_sha256
        or event.dataset_identifiers != (cloud_spec.data_sha256,)
        or event.random_seeds != cloud_spec.seeds
        or event.evaluator_outputs
        or event.reason
        != (
            "verified exact compute-escalation project equivalence, plan, "
            "and budget before GPU submission"
        )
        or thaw_json(event.metadata)
        != {"compute_escalation_plan_authority": binding}
        or any(
            candidate.event_type == "CORRECTION"
            and candidate.supersedes_event_id == event.event_id
            for candidate in events
        )
    ):
        raise ExperimentError(
            "compute escalation plan-authority checkpoint is stale or substituted"
        )
    return event, index


def _build_compute_escalation_authority(
    *,
    authority_id: str,
    run_id: str,
    ledger: EventLedger,
    input_records: tuple[ArtifactRecord, ...],
    local_spec: FrozenRunSpec,
    cloud_spec: FrozenRunSpec,
    decision: EscalationDecision,
    submission_plan: GPUCloudSubmissionPlan,
    human_gate_policy: Any,
    budget: ComputeEscalationBudget,
    expected_monetary_cost: float,
    event: LedgerEvent,
    event_index: int,
) -> ComputeEscalationPlanAuthority:
    assert event.event_hash is not None
    return ComputeEscalationPlanAuthority(
        authority_id=authority_id,
        run_id=run_id,
        ledger_path=ledger.relative_path.as_posix(),
        object_id=decision.decision_id,
        local_spec_artifact_sha256=input_records[0].sha256,
        cloud_spec_artifact_sha256=input_records[1].sha256,
        source_profile_artifact_sha256=input_records[2].sha256,
        target_profile_artifact_sha256=input_records[3].sha256,
        target_estimate_artifact_sha256=input_records[4].sha256,
        human_gate_policy_artifact_sha256=input_records[5].sha256,
        budget_artifact_sha256=input_records[6].sha256,
        decision_artifact_sha256=input_records[7].sha256,
        submission_plan_artifact_sha256=input_records[8].sha256,
        input_artifact_record_hashes=tuple(
            str(record.record_hash) for record in input_records
        ),
        local_spec_sha256=local_spec.sha256,
        cloud_spec_sha256=cloud_spec.sha256,
        project_definition_sha256=cloud_spec.project_definition_sha256,
        source_profile_sha256=local_spec.compute_profile.sha256,
        target_profile_sha256=cloud_spec.compute_profile.sha256,
        target_estimate_sha256=cloud_spec.resource_estimate.sha256,
        human_gate_policy_sha256=hashlib.sha256(
            canonical_json_bytes(_human_gate_policy_value(human_gate_policy))
        ).hexdigest(),
        budget_sha256=budget.sha256,
        decision_sha256=decision.sha256,
        submission_plan_sha256=submission_plan.sha256,
        authority_key_sha256=_compute_escalation_authority_key(
            run_id=run_id,
            object_id=decision.decision_id,
            cloud_spec_sha256=cloud_spec.sha256,
            submission_plan_sha256=submission_plan.sha256,
        ),
        expected_monetary_cost=expected_monetary_cost,
        maximum_monetary_cost=budget.maximum_monetary_cost,
        expected_wall_clock_seconds=cloud_spec.resource_estimate.wall_clock_seconds,
        maximum_total_attempts=budget.maximum_total_attempts,
        maximum_cumulative_monetary_cost=(
            budget.maximum_cumulative_monetary_cost
        ),
        maximum_cumulative_wall_clock_seconds=(
            budget.maximum_cumulative_wall_clock_seconds
        ),
        ledger_event_id=event.event_id,
        ledger_event_hash=event.event_hash,
        ledger_event_index=event_index,
        ledger_prefix_head_hash=event.event_hash,
    )


def register_compute_escalation_plan_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    authority_id: str,
    run_id: str,
    local_spec: FrozenRunSpec,
    cloud_spec: FrozenRunSpec,
    decision: EscalationDecision,
    submission_plan: GPUCloudSubmissionPlan,
    budget: ComputeEscalationBudget,
    human_gate_policy: Any = None,
) -> ArtifactRecord:
    """Register a prospective compute plan after exact deterministic replay."""

    validate_identifier(authority_id, "compute escalation authority ID")
    validate_identifier(run_id, "compute escalation run ID")
    from .gates import HumanGatePolicy, HumanGateProfile

    if human_gate_policy is None:
        human_gate_policy = HumanGatePolicy(
            HumanGateProfile.HUMAN_GATES_REQUIRED
        )
    policy_value = _human_gate_policy_value(human_gate_policy)
    if not isinstance(budget, ComputeEscalationBudget):
        raise ExperimentError("compute escalation requires a typed budget")
    expected_cost = _validate_compute_escalation_plan_inputs(
        local_spec,
        cloud_spec,
        decision,
        submission_plan,
        budget,
    )
    authority_key_sha256 = _compute_escalation_authority_key(
        run_id=run_id,
        object_id=decision.decision_id,
        cloud_spec_sha256=cloud_spec.sha256,
        submission_plan_sha256=submission_plan.sha256,
    )
    authority_id = f"compute-authority-{authority_key_sha256[:24]}"
    events = _require_compute_escalation_runtime(registry, ledger, run_id)
    _preflight_compute_escalation_authority_collision(
        events,
        authority_key_sha256=authority_key_sha256,
        local_spec_sha256=local_spec.sha256,
        decision_sha256=decision.sha256,
        human_gate_policy_sha256=hashlib.sha256(
            canonical_json_bytes(policy_value)
        ).hexdigest(),
        budget_sha256=budget.sha256,
    )
    source_profile_record = _put_compute_escalation_input(
        registry,
        run_id=run_id,
        logical_type=COMPUTE_ESCALATION_SOURCE_PROFILE_LOGICAL_TYPE,
        creator_role=Role.PROTOCOL_DESIGNER,
        value=local_spec.compute_profile.to_dict(),
    )
    target_profile_record = _put_compute_escalation_input(
        registry,
        run_id=run_id,
        logical_type=COMPUTE_ESCALATION_TARGET_PROFILE_LOGICAL_TYPE,
        creator_role=Role.PROTOCOL_DESIGNER,
        value=cloud_spec.compute_profile.to_dict(),
    )
    target_estimate_record = _put_compute_escalation_input(
        registry,
        run_id=run_id,
        logical_type=COMPUTE_ESCALATION_TARGET_ESTIMATE_LOGICAL_TYPE,
        creator_role=Role.PROTOCOL_DESIGNER,
        value=cloud_spec.resource_estimate.to_dict(),
        parents=(target_profile_record.sha256,),
    )
    policy_record = _put_compute_escalation_input(
        registry,
        run_id=run_id,
        logical_type=COMPUTE_ESCALATION_HUMAN_GATE_POLICY_LOGICAL_TYPE,
        creator_role=Role.ORCHESTRATOR,
        value=policy_value,
    )
    budget_record = _put_compute_escalation_input(
        registry,
        run_id=run_id,
        logical_type=COMPUTE_ESCALATION_BUDGET_LOGICAL_TYPE,
        creator_role=Role.PROTOCOL_DESIGNER,
        value=budget.to_dict(),
        parents=(
            target_profile_record.sha256,
            target_estimate_record.sha256,
            policy_record.sha256,
        ),
    )
    local_spec_record = _put_compute_escalation_input(
        registry,
        run_id=run_id,
        logical_type=COMPUTE_ESCALATION_LOCAL_SPEC_LOGICAL_TYPE,
        creator_role=Role.EXPERIMENT_RUNNER,
        value=local_spec.to_dict(),
        parents=(source_profile_record.sha256,),
    )
    cloud_spec_record = _put_compute_escalation_input(
        registry,
        run_id=run_id,
        logical_type=COMPUTE_ESCALATION_CLOUD_SPEC_LOGICAL_TYPE,
        creator_role=Role.EXPERIMENT_RUNNER,
        value=cloud_spec.to_dict(),
        parents=(target_profile_record.sha256, target_estimate_record.sha256),
    )
    decision_record = _put_compute_escalation_input(
        registry,
        run_id=run_id,
        logical_type=COMPUTE_ESCALATION_DECISION_LOGICAL_TYPE,
        creator_role=Role.PROTOCOL_DESIGNER,
        value=decision.to_dict(),
        parents=(
            local_spec_record.sha256,
            cloud_spec_record.sha256,
            source_profile_record.sha256,
            target_profile_record.sha256,
            target_estimate_record.sha256,
            policy_record.sha256,
            budget_record.sha256,
        ),
    )
    plan_record = _put_compute_escalation_input(
        registry,
        run_id=run_id,
        logical_type=COMPUTE_ESCALATION_PLAN_LOGICAL_TYPE,
        creator_role=Role.PROTOCOL_DESIGNER,
        value=submission_plan.to_dict(),
        parents=(
            cloud_spec_record.sha256,
            target_profile_record.sha256,
            decision_record.sha256,
            budget_record.sha256,
            policy_record.sha256,
        ),
    )
    input_records = (
        local_spec_record,
        cloud_spec_record,
        source_profile_record,
        target_profile_record,
        target_estimate_record,
        policy_record,
        budget_record,
        decision_record,
        plan_record,
    )
    event, event_index = _require_or_record_compute_escalation_event(
        registry,
        ledger,
        run_id=run_id,
        authority_id=authority_id,
        object_id=decision.decision_id,
        input_records=input_records,
        local_spec=local_spec,
        cloud_spec=cloud_spec,
        decision=decision,
        submission_plan=submission_plan,
        human_gate_policy=human_gate_policy,
        budget=budget,
        create=True,
    )
    authority = _build_compute_escalation_authority(
        authority_id=authority_id,
        run_id=run_id,
        ledger=ledger,
        input_records=input_records,
        local_spec=local_spec,
        cloud_spec=cloud_spec,
        decision=decision,
        submission_plan=submission_plan,
        human_gate_policy=human_gate_policy,
        budget=budget,
        expected_monetary_cost=expected_cost,
        event=event,
        event_index=event_index,
    )
    record = registry.put_json(
        authority.to_dict(),
        logical_type=COMPUTE_ESCALATION_PLAN_AUTHORITY_LOGICAL_TYPE,
        origin="fresh registry-and-ledger compute-escalation plan verification",
        creator_role=Role.CLAIM_VERIFIER,
        creation_command=_COMPUTE_ESCALATION_COMMAND,
        parent_artifacts=authority.input_artifact_hashes,
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )
    require_compute_escalation_plan_authority(
        registry,
        ledger,
        authority_artifact_sha256=record.sha256,
        expected_run_id=run_id,
        expected_decision_id=decision.decision_id,
    )
    return record


def require_compute_escalation_plan_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    authority_artifact_sha256: str,
    expected_run_id: str,
    expected_decision_id: str,
) -> ComputeEscalationPlanAuthority:
    """Freshly rederive an exact same-run compute-escalation plan authority."""

    _require_compute_escalation_runtime(registry, ledger, expected_run_id)
    validate_identifier(expected_decision_id, "expected escalation decision ID")
    validate_sha256(
        authority_artifact_sha256,
        "compute escalation plan-authority SHA-256",
    )
    try:
        registry.verify(authority_artifact_sha256, raise_on_error=True)
        record = registry.get_metadata(authority_artifact_sha256)
        raw = registry.get_bytes(authority_artifact_sha256)
        value = safe_json_loads(raw)
    except (ArtifactError, ValidationError) as exc:
        raise ExperimentError(
            "compute escalation plan authority cannot be reopened"
        ) from exc
    if (
        record.logical_type != COMPUTE_ESCALATION_PLAN_AUTHORITY_LOGICAL_TYPE
        or record.creator_role is not Role.CLAIM_VERIFIER
        or record.origin
        != "fresh registry-and-ledger compute-escalation plan verification"
        or record.creation_command != _COMPUTE_ESCALATION_COMMAND
        or record.schema_version != "1.0"
        or record.mime_type != "application/json"
        or record.validation_result != "PASS"
        or not record.frozen
        or not isinstance(value, Mapping)
        or raw != canonical_json_bytes(value) + b"\n"
    ):
        raise ExperimentError(
            "compute escalation plan authority metadata is not authoritative"
        )
    if value.get("schema_version") == COMPUTE_ESCALATION_PLAN_AUTHORITY_V1_SCHEMA:
        raise ExperimentError(
            "legacy v1 compute escalation authority is audit-only and non-executable"
        )
    authority = ComputeEscalationPlanAuthority.from_dict(value)
    if (
        authority.run_id != expected_run_id
        or authority.object_id != expected_decision_id
        or authority.ledger_path != ledger.relative_path.as_posix()
        or record.parent_artifacts != authority.input_artifact_hashes
    ):
        raise ExperimentError(
            "compute escalation plan authority names another run, decision, or closure"
        )
    local_record, local_value = _load_compute_escalation_input(
        registry,
        authority.local_spec_artifact_sha256,
        run_id=authority.run_id,
        logical_type=COMPUTE_ESCALATION_LOCAL_SPEC_LOGICAL_TYPE,
        creator_role=Role.EXPERIMENT_RUNNER,
    )
    cloud_record, cloud_value = _load_compute_escalation_input(
        registry,
        authority.cloud_spec_artifact_sha256,
        run_id=authority.run_id,
        logical_type=COMPUTE_ESCALATION_CLOUD_SPEC_LOGICAL_TYPE,
        creator_role=Role.EXPERIMENT_RUNNER,
    )
    source_profile_record, source_profile_value = _load_compute_escalation_input(
        registry,
        authority.source_profile_artifact_sha256,
        run_id=authority.run_id,
        logical_type=COMPUTE_ESCALATION_SOURCE_PROFILE_LOGICAL_TYPE,
        creator_role=Role.PROTOCOL_DESIGNER,
    )
    target_profile_record, target_profile_value = _load_compute_escalation_input(
        registry,
        authority.target_profile_artifact_sha256,
        run_id=authority.run_id,
        logical_type=COMPUTE_ESCALATION_TARGET_PROFILE_LOGICAL_TYPE,
        creator_role=Role.PROTOCOL_DESIGNER,
    )
    target_estimate_record, target_estimate_value = _load_compute_escalation_input(
        registry,
        authority.target_estimate_artifact_sha256,
        run_id=authority.run_id,
        logical_type=COMPUTE_ESCALATION_TARGET_ESTIMATE_LOGICAL_TYPE,
        creator_role=Role.PROTOCOL_DESIGNER,
    )
    policy_record, policy_value = _load_compute_escalation_input(
        registry,
        authority.human_gate_policy_artifact_sha256,
        run_id=authority.run_id,
        logical_type=COMPUTE_ESCALATION_HUMAN_GATE_POLICY_LOGICAL_TYPE,
        creator_role=Role.ORCHESTRATOR,
    )
    budget_record, budget_value = _load_compute_escalation_input(
        registry,
        authority.budget_artifact_sha256,
        run_id=authority.run_id,
        logical_type=COMPUTE_ESCALATION_BUDGET_LOGICAL_TYPE,
        creator_role=Role.PROTOCOL_DESIGNER,
    )
    decision_record, decision_value = _load_compute_escalation_input(
        registry,
        authority.decision_artifact_sha256,
        run_id=authority.run_id,
        logical_type=COMPUTE_ESCALATION_DECISION_LOGICAL_TYPE,
        creator_role=Role.PROTOCOL_DESIGNER,
    )
    plan_record, plan_value = _load_compute_escalation_input(
        registry,
        authority.submission_plan_artifact_sha256,
        run_id=authority.run_id,
        logical_type=COMPUTE_ESCALATION_PLAN_LOGICAL_TYPE,
        creator_role=Role.PROTOCOL_DESIGNER,
    )
    input_records = (
        local_record,
        cloud_record,
        source_profile_record,
        target_profile_record,
        target_estimate_record,
        policy_record,
        budget_record,
        decision_record,
        plan_record,
    )
    local_spec = _parse_frozen_run_spec(local_value)
    cloud_spec = _parse_frozen_run_spec(cloud_value)
    source_profile = _parse_compute_profile(source_profile_value)
    target_profile = _parse_compute_profile(target_profile_value)
    target_estimate = _parse_resource_estimate(target_estimate_value)
    human_gate_policy = _parse_human_gate_policy(policy_value)
    budget = _parse_escalation_budget(budget_value)
    decision = _parse_escalation_decision(decision_value)
    submission_plan = _parse_submission_plan(plan_value)
    if (
        local_spec.compute_profile != source_profile
        or cloud_spec.compute_profile != target_profile
        or cloud_spec.resource_estimate != target_estimate
        or source_profile_record.parent_artifacts
        or target_profile_record.parent_artifacts
        or target_estimate_record.parent_artifacts
        != (target_profile_record.sha256,)
        or budget_record.parent_artifacts
        != (
            target_profile_record.sha256,
            target_estimate_record.sha256,
            policy_record.sha256,
        )
        or policy_record.parent_artifacts
        or local_record.parent_artifacts != (source_profile_record.sha256,)
        or cloud_record.parent_artifacts
        != (target_profile_record.sha256, target_estimate_record.sha256)
        or decision_record.parent_artifacts
        != (
            local_record.sha256,
            cloud_record.sha256,
            source_profile_record.sha256,
            target_profile_record.sha256,
            target_estimate_record.sha256,
            policy_record.sha256,
            budget_record.sha256,
        )
        or plan_record.parent_artifacts
        != (
            cloud_record.sha256,
            target_profile_record.sha256,
            decision_record.sha256,
            budget_record.sha256,
            policy_record.sha256,
        )
    ):
        raise ExperimentError(
            "compute escalation typed inputs or parent closure are substituted"
        )
    expected_cost = _validate_compute_escalation_plan_inputs(
        local_spec,
        cloud_spec,
        decision,
        submission_plan,
        budget,
    )
    event, event_index = _require_or_record_compute_escalation_event(
        registry,
        ledger,
        run_id=authority.run_id,
        authority_id=authority.authority_id,
        object_id=authority.object_id,
        input_records=input_records,
        local_spec=local_spec,
        cloud_spec=cloud_spec,
        decision=decision,
        submission_plan=submission_plan,
        human_gate_policy=human_gate_policy,
        budget=budget,
        create=False,
    )
    expected = _build_compute_escalation_authority(
        authority_id=authority.authority_id,
        run_id=authority.run_id,
        ledger=ledger,
        input_records=input_records,
        local_spec=local_spec,
        cloud_spec=cloud_spec,
        decision=decision,
        submission_plan=submission_plan,
        human_gate_policy=human_gate_policy,
        budget=budget,
        expected_monetary_cost=expected_cost,
        event=event,
        event_index=event_index,
    )
    expected_authority_id = f"compute-authority-{authority.authority_key_sha256[:24]}"
    if (
        authority != expected
        or authority.authority_id != expected_authority_id
        or authority.human_gate_policy_sha256
        != hashlib.sha256(canonical_json_bytes(policy_value)).hexdigest()
        or authority.scientific_gate_passed is not True
    ):
        raise ExperimentError(
            "compute escalation plan authority differs from fresh replay"
        )
    return authority


def _compute_escalation_gate_payload(authorization: Any) -> dict[str, Any]:
    decision = authorization.decision
    if decision is None:
        raise ExperimentError(
            "scheduled GPU authorization lacks an autonomous decision"
        )
    return {
        "gate": authorization.gate.value,
        "outcome": authorization.outcome.value,
        "scientific_gate_passed": authorization.scientific_gate_passed,
        "scientific_authority_hash": authorization.scientific_authority_hash,
        "scientific_authority_type": authorization.scientific_authority_type,
        "scientific_object_id": authorization.scientific_object_id,
        "reason": authorization.reason,
        "decision": {
            "decision_id": decision.decision_id,
            "gate": decision.gate.value,
            "scientific_authority_hash": decision.scientific_authority_hash,
            "alternatives": list(decision.alternatives),
            "evidence_hashes": list(decision.evidence_hashes),
            "governing_rule": decision.governing_rule,
            "uncertainty": decision.uncertainty,
            "reason": decision.reason,
            "downstream_consequences": list(
                decision.downstream_consequences
            ),
        },
    }


def register_compute_escalation_submission_authorization(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    authority_artifact_sha256: str,
    authority_run_id: str,
    local_spec: FrozenRunSpec,
    cloud_spec: FrozenRunSpec,
    decision: EscalationDecision,
    idempotency_key: str,
    autonomous_decision: Any,
) -> ArtifactRecord:
    """Persist the exact gate policy and replayable autonomous authorization.

    The returned artifact is a submission-scoped input, not human authority.
    The scheduled backend reopens and re-evaluates it immediately before it
    consumes the one-shot plan authority.
    """

    from .gates import (
        AuthorizationOutcome,
        AutonomousDecisionRecord,
        HumanGate,
    )

    _require_compute_escalation_runtime(registry, ledger, authority_run_id)
    validate_identifier(idempotency_key, "scheduled GPU idempotency key")
    if type(autonomous_decision) is not AutonomousDecisionRecord:
        raise ExperimentError(
            "scheduled GPU submission decision must be an exact typed value"
        )
    authority = require_compute_escalation_plan_authority(
        registry,
        ledger,
        authority_artifact_sha256=authority_artifact_sha256,
        expected_run_id=authority_run_id,
        expected_decision_id=decision.decision_id,
    )
    _, plan_value = _load_compute_escalation_input(
        registry,
        authority.submission_plan_artifact_sha256,
        run_id=authority_run_id,
        logical_type=COMPUTE_ESCALATION_PLAN_LOGICAL_TYPE,
        creator_role=Role.PROTOCOL_DESIGNER,
    )
    plan = _parse_submission_plan(plan_value)
    request = ScheduledGPURequest(cloud_spec, plan, idempotency_key)
    _, policy_value = _load_compute_escalation_input(
        registry,
        authority.human_gate_policy_artifact_sha256,
        run_id=authority_run_id,
        logical_type=COMPUTE_ESCALATION_HUMAN_GATE_POLICY_LOGICAL_TYPE,
        creator_role=Role.ORCHESTRATOR,
    )
    gate_policy = _parse_human_gate_policy(policy_value)
    if (
        authority.local_spec_sha256 != local_spec.sha256
        or authority.cloud_spec_sha256 != cloud_spec.sha256
        or authority.project_definition_sha256
        != cloud_spec.project_definition_sha256
        or authority.decision_sha256 != decision.sha256
        or authority.submission_plan_sha256 != plan.sha256
        or authority.expected_monetary_cost
        > authority.maximum_monetary_cost
    ):
        raise ExperimentError(
            "scheduled GPU authority names another run, plan, or budget"
        )
    events = ledger.events()
    if (
        not events
        or events[-1].event_id != authority.ledger_event_id
        or events[-1].event_hash != authority.ledger_event_hash
    ):
        raise ExperimentError(
            "compute escalation authority is not the fresh ledger head"
        )
    try:
        authorization = gate_policy.evaluate(
            registry,
            HumanGate.COMPUTE_ESCALATION,
            scientific_authority_hash=authority_artifact_sha256,
            expected_object_id=decision.decision_id,
            ledger=ledger,
            expected_run_id=authority_run_id,
            autonomous_decision=autonomous_decision,
        )
    except ValidationError as exc:
        raise ExperimentError(
            "configured gate policy does not authorize autonomous GPU submission"
        ) from exc
    if authorization.outcome is not AuthorizationOutcome.AUTHORIZED_AUTONOMOUSLY:
        raise ExperimentError(
            "configured gate policy does not authorize autonomous GPU submission"
        )
    gate_payload = _compute_escalation_gate_payload(authorization)
    payload = {
        "schema_version": COMPUTE_ESCALATION_SUBMISSION_AUTHORIZATION_SCHEMA,
        "run_id": authority_run_id,
        "authority_artifact_sha256": authority_artifact_sha256,
        "authority_id": authority.authority_id,
        "authority_key_sha256": authority.authority_key_sha256,
        "local_spec_sha256": local_spec.sha256,
        "cloud_spec_sha256": cloud_spec.sha256,
        "project_definition_sha256": cloud_spec.project_definition_sha256,
        "submission_plan_sha256": plan.sha256,
        "decision_sha256": decision.sha256,
        "budget_artifact_sha256": authority.budget_artifact_sha256,
        "budget_sha256": authority.budget_sha256,
        "expected_monetary_cost": authority.expected_monetary_cost,
        "maximum_monetary_cost": authority.maximum_monetary_cost,
        "expected_wall_clock_seconds": authority.expected_wall_clock_seconds,
        "human_gate_policy_artifact_sha256": (
            authority.human_gate_policy_artifact_sha256
        ),
        "human_gate_policy_sha256": authority.human_gate_policy_sha256,
        "maximum_total_attempts": authority.maximum_total_attempts,
        "maximum_cumulative_monetary_cost": (
            authority.maximum_cumulative_monetary_cost
        ),
        "maximum_cumulative_wall_clock_seconds": (
            authority.maximum_cumulative_wall_clock_seconds
        ),
        "idempotency_key": idempotency_key,
        "request_sha256": hashlib.sha256(
            canonical_json_bytes(request.to_dict())
        ).hexdigest(),
        "policy": {
            "profile": gate_policy.profile.value,
            "selective_gates": [item.value for item in gate_policy.selective_gates],
        },
        "authorization": gate_payload,
    }
    return registry.put_json(
        payload,
        logical_type=COMPUTE_ESCALATION_SUBMISSION_AUTHORIZATION_LOGICAL_TYPE,
        origin=_COMPUTE_ESCALATION_SUBMISSION_AUTHORIZATION_ORIGIN,
        creator_role=Role.ORCHESTRATOR,
        creation_command=_COMPUTE_ESCALATION_SUBMISSION_AUTHORIZATION_COMMAND,
        parent_artifacts=(authority_artifact_sha256,),
        schema_version="1.0",
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )


def _require_compute_escalation_submission_authorization(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    submission_authorization_artifact_sha256: str,
    authority_artifact_sha256: str,
    authority_run_id: str,
    authority: ComputeEscalationPlanAuthority,
    local_spec: FrozenRunSpec,
    cloud_spec: FrozenRunSpec,
    decision: EscalationDecision,
    plan: GPUCloudSubmissionPlan,
    request: ScheduledGPURequest,
    expected_autonomous_decision: Any = None,
) -> str:
    from .gates import (
        AuthorizationOutcome,
        AutonomousDecisionRecord,
        HumanGate,
        HumanGatePolicy,
        HumanGateProfile,
    )

    validate_sha256(
        submission_authorization_artifact_sha256,
        "compute escalation submission-authorization SHA-256",
    )
    try:
        registry.verify(
            submission_authorization_artifact_sha256,
            raise_on_error=True,
        )
        record = registry.get_metadata(
            submission_authorization_artifact_sha256
        )
        raw = registry.get_bytes(submission_authorization_artifact_sha256)
        value = safe_json_loads(raw)
    except (ArtifactError, ValidationError) as exc:
        raise ExperimentError(
            "compute escalation submission authorization cannot be reopened"
        ) from exc
    expected_fields = {
        "schema_version",
        "run_id",
        "authority_artifact_sha256",
        "authority_id",
        "authority_key_sha256",
        "local_spec_sha256",
        "cloud_spec_sha256",
        "project_definition_sha256",
        "submission_plan_sha256",
        "decision_sha256",
        "budget_artifact_sha256",
        "budget_sha256",
        "expected_monetary_cost",
        "maximum_monetary_cost",
        "expected_wall_clock_seconds",
        "human_gate_policy_artifact_sha256",
        "human_gate_policy_sha256",
        "maximum_total_attempts",
        "maximum_cumulative_monetary_cost",
        "maximum_cumulative_wall_clock_seconds",
        "idempotency_key",
        "request_sha256",
        "policy",
        "authorization",
    }
    if (
        record.logical_type
        != COMPUTE_ESCALATION_SUBMISSION_AUTHORIZATION_LOGICAL_TYPE
        or record.creator_role is not Role.ORCHESTRATOR
        or record.origin != _COMPUTE_ESCALATION_SUBMISSION_AUTHORIZATION_ORIGIN
        or record.creation_command
        != _COMPUTE_ESCALATION_SUBMISSION_AUTHORIZATION_COMMAND
        or record.parent_artifacts != (authority_artifact_sha256,)
        or record.schema_version != "1.0"
        or record.mime_type != "application/json"
        or record.validation_result != "PASS"
        or not record.frozen
        or not isinstance(value, Mapping)
        or set(value) != expected_fields
        or raw != canonical_json_bytes(value) + b"\n"
        or value.get("schema_version")
        != COMPUTE_ESCALATION_SUBMISSION_AUTHORIZATION_SCHEMA
        or value.get("run_id") != authority_run_id
        or value.get("authority_artifact_sha256")
        != authority_artifact_sha256
        or value.get("authority_id") != authority.authority_id
        or value.get("authority_key_sha256")
        != authority.authority_key_sha256
        or value.get("local_spec_sha256") != local_spec.sha256
        or value.get("cloud_spec_sha256") != cloud_spec.sha256
        or value.get("project_definition_sha256")
        != cloud_spec.project_definition_sha256
        or value.get("submission_plan_sha256") != plan.sha256
        or value.get("decision_sha256") != decision.sha256
        or value.get("budget_artifact_sha256")
        != authority.budget_artifact_sha256
        or value.get("budget_sha256") != authority.budget_sha256
        or value.get("expected_monetary_cost")
        != authority.expected_monetary_cost
        or value.get("maximum_monetary_cost")
        != authority.maximum_monetary_cost
        or value.get("expected_wall_clock_seconds")
        != authority.expected_wall_clock_seconds
        or value.get("human_gate_policy_artifact_sha256")
        != authority.human_gate_policy_artifact_sha256
        or value.get("human_gate_policy_sha256")
        != authority.human_gate_policy_sha256
        or value.get("maximum_total_attempts")
        != authority.maximum_total_attempts
        or value.get("maximum_cumulative_monetary_cost")
        != authority.maximum_cumulative_monetary_cost
        or value.get("maximum_cumulative_wall_clock_seconds")
        != authority.maximum_cumulative_wall_clock_seconds
        or value.get("idempotency_key") != request.idempotency_key
        or value.get("request_sha256")
        != hashlib.sha256(
            canonical_json_bytes(request.to_dict())
        ).hexdigest()
    ):
        raise ExperimentError(
            "compute escalation submission authorization is not exactly bound"
        )
    policy_value = value["policy"]
    authorization_value = value["authorization"]
    if (
        not isinstance(policy_value, Mapping)
        or set(policy_value) != {"profile", "selective_gates"}
        or not isinstance(policy_value.get("selective_gates"), list)
        or not isinstance(authorization_value, Mapping)
    ):
        raise ExperimentError(
            "compute escalation gate policy or authorization is malformed"
        )
    try:
        policy = HumanGatePolicy(
            HumanGateProfile(policy_value["profile"]),
            tuple(HumanGate(item) for item in policy_value["selective_gates"]),
        )
        decision_value = authorization_value["decision"]
        if not isinstance(decision_value, Mapping) or set(decision_value) != {
            "decision_id",
            "gate",
            "scientific_authority_hash",
            "alternatives",
            "evidence_hashes",
            "governing_rule",
            "uncertainty",
            "reason",
            "downstream_consequences",
        }:
            raise ExperimentError(
                "compute escalation autonomous decision is malformed"
            )
        autonomous_decision = AutonomousDecisionRecord(
            decision_id=decision_value["decision_id"],
            gate=HumanGate(decision_value["gate"]),
            scientific_authority_hash=decision_value[
                "scientific_authority_hash"
            ],
            alternatives=tuple(decision_value["alternatives"]),
            evidence_hashes=tuple(decision_value["evidence_hashes"]),
            governing_rule=decision_value["governing_rule"],
            uncertainty=decision_value["uncertainty"],
            reason=decision_value["reason"],
            downstream_consequences=tuple(
                decision_value["downstream_consequences"]
            ),
        )
        replayed = policy.evaluate(
            registry,
            HumanGate.COMPUTE_ESCALATION,
            scientific_authority_hash=authority_artifact_sha256,
            expected_object_id=decision.decision_id,
            ledger=ledger,
            expected_run_id=authority_run_id,
            autonomous_decision=autonomous_decision,
        )
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise ExperimentError(
            "compute escalation gate policy cannot be replayed"
        ) from exc
    if (
        expected_autonomous_decision is not None
        and autonomous_decision != expected_autonomous_decision
    ):
        raise ExperimentError(
            "compute escalation autonomous decision differs from its frozen replay"
        )
    _, authority_policy_value = _load_compute_escalation_input(
        registry,
        authority.human_gate_policy_artifact_sha256,
        run_id=authority_run_id,
        logical_type=COMPUTE_ESCALATION_HUMAN_GATE_POLICY_LOGICAL_TYPE,
        creator_role=Role.ORCHESTRATOR,
    )
    if (
        dict(policy_value) != dict(authority_policy_value)
        or hashlib.sha256(canonical_json_bytes(policy_value)).hexdigest()
        != authority.human_gate_policy_sha256
        or replayed.outcome
        is not AuthorizationOutcome.AUTHORIZED_AUTONOMOUSLY
        or _compute_escalation_gate_payload(replayed)
        != dict(authorization_value)
    ):
        raise ExperimentError(
            "compute escalation gate authorization differs from policy replay"
        )
    return hashlib.sha256(canonical_json_bytes(authorization_value)).hexdigest()


@dataclass(frozen=True)
class ScheduledGPURequest:
    """Secret-free structured request passed to an injected scheduler transport."""

    spec: FrozenRunSpec
    submission_plan: GPUCloudSubmissionPlan
    idempotency_key: str

    def __post_init__(self) -> None:
        if not isinstance(self.spec, FrozenRunSpec):
            raise ExperimentError("scheduled GPU request requires a frozen run spec")
        if not isinstance(self.submission_plan, GPUCloudSubmissionPlan):
            raise ExperimentError("scheduled GPU request requires a typed submission plan")
        validate_identifier(self.idempotency_key, "scheduled GPU idempotency key")
        if self.spec.compute_profile.mode is not ComputeMode.GPU_CLOUD:
            raise ExperimentError("scheduled request requires a GPU_CLOUD run spec")
        if self.submission_plan.spec_sha256 != self.spec.sha256:
            raise ExperimentIntegrityError("scheduled request plan does not bind its run spec")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "SCIENTIST_ONE_SCHEDULED_GPU_REQUEST_V1",
            "spec": self.spec.to_dict(),
            "submission_plan": self.submission_plan.to_dict(),
            "idempotency_key": self.idempotency_key,
        }


@dataclass(frozen=True)
class ScheduledGPUStatus:
    provider_job_id: str
    state: RunState
    reason: str | None = None
    checkpoint_token: str | None = None
    queue_position: int | None = None
    attempt: int = 1
    external_validation: ValidationStatus = ValidationStatus.UNTESTED

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "provider_job_id",
            _opaque_reference(self.provider_job_id, "provider GPU job ID"),
        )
        if not isinstance(self.state, RunState):
            try:
                object.__setattr__(self, "state", RunState(self.state))
            except (TypeError, ValueError) as exc:
                raise ExperimentError("unknown scheduled GPU state") from exc
        if self.reason is not None:
            object.__setattr__(self, "reason", _bounded_text(self.reason, "GPU status reason"))
        if self.checkpoint_token is not None:
            object.__setattr__(
                self,
                "checkpoint_token",
                _opaque_reference(self.checkpoint_token, "GPU checkpoint token", 4_096),
            )
        if self.state is RunState.PREEMPTED and self.checkpoint_token is None:
            raise ExperimentError("preempted GPU status requires a checkpoint token")
        if (
            self.queue_position is not None
            and (
                isinstance(self.queue_position, bool)
                or not isinstance(self.queue_position, int)
                or not 0 <= self.queue_position <= 10_000_000
            )
        ):
            raise ExperimentError("scheduled GPU queue position is invalid")
        if (
            isinstance(self.attempt, bool)
            or not isinstance(self.attempt, int)
            or not 1 <= self.attempt <= 10_000
        ):
            raise ExperimentError("scheduled GPU attempt is invalid")
        if self.external_validation is not ValidationStatus.UNTESTED:
            raise ExperimentError("scheduled GPU status remains externally UNTESTED")


@dataclass(frozen=True)
class ScheduledGPUArtifactBundle:
    manifest: OutputManifest
    artifacts: tuple[StagedArtifact, ...]
    manifest_bytes: bytes = field(repr=False)
    provider_job_id: str
    spec_sha256: str
    submission_plan_sha256: str
    attempt: int
    resumed_checkpoint_sha256: str | None
    requeue_history: tuple[GPURequeueLineage, ...]
    external_validation: ValidationStatus = ValidationStatus.UNTESTED

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, OutputManifest):
            raise ExperimentError("scheduled GPU bundle manifest must be typed")
        if not isinstance(self.manifest_bytes, bytes):
            raise ExperimentError(
                "scheduled GPU bundle manifest bytes must be immutable bytes"
            )
        if len(self.manifest_bytes) > MAX_OUTPUT_MANIFEST_BYTES:
            raise ExperimentError(
                "scheduled GPU bundle manifest exceeds the byte bound"
            )
        try:
            manifest_value = safe_json_loads(
                self.manifest_bytes,
                max_bytes=MAX_OUTPUT_MANIFEST_BYTES,
            )
        except ValidationError as exc:
            raise ExperimentIntegrityError(
                "scheduled GPU bundle manifest bytes are malformed"
            ) from exc
        if (
            not isinstance(manifest_value, Mapping)
            or dict(manifest_value) != self.manifest.to_dict()
        ):
            raise ExperimentIntegrityError(
                "scheduled GPU bundle manifest bytes differ from its typed manifest"
            )
        if not isinstance(self.artifacts, tuple) or not all(
            isinstance(item, StagedArtifact) for item in self.artifacts
        ):
            raise ExperimentError("scheduled GPU bundle artifacts must be a typed tuple")
        if len(self.artifacts) > MAX_OUTPUT_ARTIFACTS:
            raise ExperimentError("scheduled GPU bundle exceeds the artifact-count bound")
        if sum(len(item.payload) for item in self.artifacts) > MAX_RETURNED_ARTIFACT_TOTAL_BYTES:
            raise ExperimentError("scheduled GPU bundle exceeds the artifact-byte bound")
        if tuple(item.descriptor for item in self.artifacts) != self.manifest.artifacts:
            raise ExperimentIntegrityError("scheduled GPU bundle differs from its manifest")
        object.__setattr__(
            self,
            "provider_job_id",
            _opaque_reference(self.provider_job_id, "provider GPU bundle job ID"),
        )
        validate_sha256(self.spec_sha256, "GPU bundle spec SHA-256")
        validate_sha256(
            self.submission_plan_sha256,
            "GPU bundle submission-plan SHA-256",
        )
        if self.spec_sha256 != self.manifest.spec_sha256:
            raise ExperimentIntegrityError("scheduled GPU bundle spec differs from its manifest")
        if (
            isinstance(self.attempt, bool)
            or not isinstance(self.attempt, int)
            or not 1 <= self.attempt <= 10_000
        ):
            raise ExperimentError("scheduled GPU bundle attempt is invalid")
        if self.resumed_checkpoint_sha256 is not None:
            validate_sha256(
                self.resumed_checkpoint_sha256,
                "GPU bundle resumed checkpoint SHA-256",
            )
        if not isinstance(self.requeue_history, tuple) or not all(
            isinstance(item, GPURequeueLineage) for item in self.requeue_history
        ):
            raise ExperimentError("scheduled GPU bundle requeue history must be typed")
        if len(self.requeue_history) > 10_000:
            raise ExperimentError("scheduled GPU bundle requeue history exceeds its bound")
        if self.external_validation is not ValidationStatus.UNTESTED:
            raise ExperimentError("scheduled GPU artifact return remains externally UNTESTED")


@dataclass(frozen=True)
class GPURequeueLineage:
    source_attempt: int
    target_attempt: int
    checkpoint_sha256: str
    action_idempotency_key: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.source_attempt, bool)
            or not isinstance(self.source_attempt, int)
            or not 1 <= self.source_attempt < 10_000
            or isinstance(self.target_attempt, bool)
            or not isinstance(self.target_attempt, int)
            or self.target_attempt != self.source_attempt + 1
        ):
            raise ExperimentError("GPU requeue lineage must advance exactly one attempt")
        validate_sha256(self.checkpoint_sha256, "GPU requeue checkpoint SHA-256")
        validate_identifier(self.action_idempotency_key, "GPU requeue action key")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_attempt": self.source_attempt,
            "target_attempt": self.target_attempt,
            "checkpoint_sha256": self.checkpoint_sha256,
            "action_idempotency_key": self.action_idempotency_key,
        }


@runtime_checkable
class ScheduledGPUTransport(Protocol):
    """Structured scheduler seam; implementations own any network or CLI access."""

    @property
    def provider_name(self) -> str: ...

    @property
    def capabilities(self) -> GPUCloudCapabilities: ...

    @property
    def network_used(self) -> bool: ...

    @property
    def validation_status(self) -> ValidationStatus: ...

    def submit(self, request: ScheduledGPURequest) -> ScheduledGPUStatus: ...

    def status(self, provider_job_id: str) -> ScheduledGPUStatus: ...

    def cancel(self, provider_job_id: str, *, idempotency_key: str) -> ScheduledGPUStatus: ...

    def requeue(
        self,
        provider_job_id: str,
        *,
        checkpoint_token: str,
        idempotency_key: str,
    ) -> ScheduledGPUStatus: ...

    def collect(self, provider_job_id: str) -> ScheduledGPUArtifactBundle: ...


@dataclass(frozen=True)
class RegisteredGPUArtifacts:
    collected_run: CollectedRun
    source_spec_record: ArtifactRecord
    target_spec_record: ArtifactRecord
    submission_plan_record: ArtifactRecord
    escalation_decision_record: ArtifactRecord
    manifest_record: ArtifactRecord
    return_receipt_record: ArtifactRecord
    artifact_records: tuple[ArtifactRecord, ...]
    external_validation: ValidationStatus = ValidationStatus.UNTESTED

    def __post_init__(self) -> None:
        if not isinstance(self.collected_run, CollectedRun):
            raise ExperimentError("registered GPU return requires a collected run")
        for name in (
            "source_spec_record",
            "target_spec_record",
            "submission_plan_record",
            "escalation_decision_record",
            "manifest_record",
            "return_receipt_record",
        ):
            if not isinstance(getattr(self, name), ArtifactRecord):
                raise ExperimentError(f"registered GPU {name} must be typed")
        if not isinstance(self.artifact_records, tuple) or not all(
            isinstance(item, ArtifactRecord) for item in self.artifact_records
        ):
            raise ExperimentError("registered GPU artifact records must be a typed tuple")
        if tuple(item.sha256 for item in self.artifact_records) != (
            self.collected_run.returned_artifact_sha256s
        ):
            raise ExperimentIntegrityError("registered GPU records differ from collected artifacts")
        if self.target_spec_record.sha256 != self.collected_run.spec.sha256:
            raise ExperimentIntegrityError("registered GPU target spec differs from collected run")
        if self.manifest_record.sha256 != self.collected_run.manifest_sha256:
            raise ExperimentIntegrityError("registered GPU manifest differs from collected run")
        if (
            self.collected_run.validation_status is not ValidationStatus.UNTESTED
            or self.collected_run.scientific_evidence
            or self.collected_run.network_isolation_attested
        ):
            raise ExperimentIntegrityError("registered GPU return overstates validation")
        if any(
            self.return_receipt_record.sha256 not in item.parent_artifacts
            for item in self.artifact_records
        ):
            raise ExperimentIntegrityError("GPU artifact records lack their UNTESTED return receipt")
        required_receipt_parents = {
            self.source_spec_record.sha256,
            self.target_spec_record.sha256,
            self.submission_plan_record.sha256,
            self.escalation_decision_record.sha256,
            self.manifest_record.sha256,
        }
        if not required_receipt_parents.issubset(
            set(self.return_receipt_record.parent_artifacts)
        ):
            raise ExperimentIntegrityError("GPU return receipt lacks frozen execution lineage")
        if self.external_validation is not ValidationStatus.UNTESTED:
            raise ExperimentError("registered GPU return remains externally UNTESTED")


@dataclass
class _ScheduledGPUJob:
    local_spec: FrozenRunSpec
    cloud_spec: FrozenRunSpec
    decision: EscalationDecision
    plan: GPUCloudSubmissionPlan
    idempotency_key: str
    job_id: str
    provider_job_id: str
    state: RunState
    attempt: int
    network_used: bool
    authority_artifact_sha256: str
    authority_run_id: str
    authority_id: str
    authority_key_sha256: str
    submission_authorization_artifact_sha256: str
    gate_authorization_sha256: str
    request_sha256: str
    reason: str | None = None
    checkpoint_token: str | None = None
    # The token is volatile and exists only while a job is PREEMPTED.  The
    # resumed lineage is durable solely as this digest.
    requeued_checkpoint_sha256: str | None = None
    requeued_from_attempt: int | None = None
    requeue_history: tuple[GPURequeueLineage, ...] = ()
    queue_position: int | None = None
    bundle: ScheduledGPUArtifactBundle | None = None
    # These are registry/ledger identities, not scheduler-provided state.  A
    # checkpoint token deliberately never crosses this persistence boundary.
    snapshot_sha256: str | None = None
    snapshot_event_id: str | None = None
    pending_checkpoint_sha256: str | None = None
    pending_action_key: str | None = None
    causal_consumption_action_key: str | None = None
    causal_consumption_event_id: str | None = None
    causal_consumption_event_hash: str | None = None
    collected_manifest_sha256: str | None = None
    collected_artifact_sha256s: tuple[str, ...] = ()
    collected_bundle_sha256: str | None = None
    # Volatile fail-closed marker.  A validated provider response that could
    # not be durably admitted must never become observable through a later
    # same-process retry.
    durability_blocked: bool = False


class ScheduledGPURecoveryBlocked(ExperimentError):
    """A paid scheduler side effect may have happened and cannot be replayed.

    This is intentionally not a ``RunState``.  It describes a backend
    disposition: callers may perform read-only reconciliation, but must not
    issue another submit, requeue, or cancel merely because a process died in
    the response window.
    """


_SCHEDULED_GPU_RECOVERY_SCHEMA = "scheduled-gpu-recovery-snapshot/v1"
_SCHEDULED_GPU_RECOVERY_LOGICAL_TYPE = "scheduled_gpu_recovery_snapshot"
_SCHEDULED_GPU_RECOVERY_COMMAND = (
    "scientist-one",
    "record-scheduled-gpu-recovery-snapshot",
)
_MAX_SCHEDULED_GPU_SNAPSHOTS_PER_JOB = 64
_SCHEDULED_GPU_RECOVERY_FIELDS = frozenset(
    {
        "schema_version",
        "backend_id",
        "provider_name",
        "job_id",
        "provider_job_id",
        "idempotency_key",
        "state",
        "attempt",
        "network_used",
        "validation_status",
        "scientific_evidence",
        "local_spec",
        "cloud_spec",
        "decision",
        "plan",
        "authority_artifact_sha256",
        "authority_run_id",
        "authority_id",
        "authority_key_sha256",
        "submission_authorization_artifact_sha256",
        "gate_authorization_sha256",
        "request_sha256",
        "pending_checkpoint_sha256",
        "requeued_checkpoint_sha256",
        "requeued_from_attempt",
        "requeue_history",
        "queue_position",
        "prior_snapshot_sha256",
        "prior_snapshot_event_id",
        "pending_action_key",
        "causal_consumption_action_key",
        "causal_consumption_event_id",
        "causal_consumption_event_hash",
        "collected_manifest_sha256",
        "collected_artifact_sha256s",
        "collected_bundle_sha256",
    }
)


class ScheduledGPUCloudBackend:
    """Concrete provider-neutral adapter over an injected structured scheduler.

    The adapter implements orchestration and registry return without importing
    shell or network primitives.  Its live infrastructure validation remains
    ``UNTESTED``; even a successful remote lifecycle is non-evidentiary until
    separate external validation is completed.
    """

    backend_id = "scheduled-gpu-cloud"
    validation_status = ValidationStatus.UNTESTED
    scientific_evidence = False

    _ALLOWED_TRANSITIONS: Mapping[RunState, frozenset[RunState]] = MappingProxyType(
        {
            RunState.SUBMITTED: frozenset(
                {
                    RunState.SUBMITTED,
                    RunState.QUEUED,
                    RunState.RUNNING,
                    RunState.PREEMPTED,
                    RunState.SUCCEEDED,
                    RunState.FAILED,
                    RunState.CANCELLED,
                }
            ),
            RunState.QUEUED: frozenset(
                {
                    RunState.QUEUED,
                    RunState.RUNNING,
                    RunState.PREEMPTED,
                    RunState.SUCCEEDED,
                    RunState.FAILED,
                    RunState.CANCELLED,
                }
            ),
            RunState.RUNNING: frozenset(
                {
                    RunState.RUNNING,
                    RunState.PREEMPTED,
                    RunState.SUCCEEDED,
                    RunState.FAILED,
                    RunState.CANCELLED,
                }
            ),
            RunState.PREEMPTED: frozenset(
                {
                    RunState.PREEMPTED,
                    RunState.QUEUED,
                    RunState.RUNNING,
                    RunState.CANCELLED,
                }
            ),
            RunState.SUCCEEDED: frozenset({RunState.SUCCEEDED}),
            RunState.FAILED: frozenset({RunState.FAILED}),
            RunState.CANCELLED: frozenset({RunState.CANCELLED}),
            RunState.INVALID_OUTPUT: frozenset({RunState.INVALID_OUTPUT}),
        }
    )

    def __init__(
        self,
        transport: ScheduledGPUTransport,
        *,
        artifact_registry: ArtifactRegistry | None = None,
        event_ledger: EventLedger | None = None,
    ) -> None:
        if not isinstance(transport, ScheduledGPUTransport):
            raise ExperimentError("scheduled GPU transport does not implement the contract")
        if not isinstance(transport.capabilities, GPUCloudCapabilities):
            raise ExperimentError("scheduled GPU transport capabilities must be typed")
        if (
            not transport.capabilities.scheduled_execution
            or not transport.capabilities.checkpoints
            or not transport.capabilities.queues
            or not transport.capabilities.artifact_return
        ):
            raise ExperimentError(
                "scheduled GPU transport lacks scheduling, queue, checkpoint, or artifact return"
            )
        if transport.validation_status is not ValidationStatus.UNTESTED:
            raise ExperimentError("scheduled GPU transport must remain externally UNTESTED")
        if not isinstance(transport.network_used, bool):
            raise ExperimentError("scheduled GPU transport network marker must be boolean")
        if artifact_registry is not None and not isinstance(artifact_registry, ArtifactRegistry):
            raise ExperimentError("artifact_registry must be an ArtifactRegistry")
        if event_ledger is not None and not isinstance(event_ledger, EventLedger):
            raise ExperimentError("event_ledger must be an EventLedger")
        if (artifact_registry is None) != (event_ledger is None):
            raise ExperimentError(
                "scheduled GPU authority requires a paired registry and ledger"
            )
        self._transport = transport
        self._registry = artifact_registry
        self._ledger = event_ledger
        self._provider_name = _opaque_reference(
            transport.provider_name,
            "scheduled GPU provider name",
            256,
        )
        self._jobs: dict[str, _ScheduledGPUJob] = {}
        self._idempotency: dict[str, tuple[str, str, str]] = {}
        self._spec_jobs: dict[str, str] = {}
        self._provider_jobs: dict[str, str] = {}
        self._lock = threading.RLock()
        # A backend instance has no authority to infer jobs from its own
        # memory.  Recovery is ledger-headed and all maps are installed only
        # after the complete source-owned chain has replayed.
        if self._registry is not None:
            self._restore_durable_jobs()

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def capabilities(self) -> GPUCloudCapabilities:
        return self._transport.capabilities

    @property
    def network_used(self) -> bool:
        with self._lock:
            return self._transport_network_snapshot() or any(
                job.network_used for job in self._jobs.values()
            )

    @property
    def network_use_status(self) -> NetworkUseStatus:
        return (
            NetworkUseStatus.USED
            if self.network_used
            else NetworkUseStatus.UNKNOWN_UNATTESTED
        )

    def _transport_network_snapshot(self) -> bool:
        network_used = self._transport.network_used
        if not isinstance(network_used, bool):
            raise ExperimentError("scheduler transport network marker changed type")
        return network_used

    def _record_transport_network_use(self, job: _ScheduledGPUJob) -> None:
        # Preserve per-job history instead of exposing a mutable transport-wide
        # flag as though it described every prior invocation.
        job.network_used = job.network_used or self._transport_network_snapshot()

    def _job(self, job_id: str) -> _ScheduledGPUJob:
        validate_identifier(job_id, "scheduled GPU job ID")
        try:
            job = self._jobs[job_id]
        except KeyError as exc:
            raise ExperimentError("unknown scheduled GPU job") from exc
        if job.durability_blocked:
            raise ScheduledGPURecoveryBlocked(
                "scheduled GPU response was not durably admitted"
            )
        return job

    @staticmethod
    def _stage_job(job: _ScheduledGPUJob) -> _ScheduledGPUJob:
        """Return an unexposed copy for validate -> persist -> publish."""

        from dataclasses import replace

        return replace(job)

    def _receipt(self, job: _ScheduledGPUJob) -> SubmissionReceipt:
        return SubmissionReceipt(
            backend_id=self.backend_id,
            job_id=job.job_id,
            idempotency_key=job.idempotency_key,
            spec_sha256=job.cloud_spec.sha256,
            state=job.state,
            validation_status=ValidationStatus.UNTESTED,
            network_used=job.network_used,
            scientific_evidence=False,
            execution_plan_sha256=job.plan.sha256,
            resumed_from_checkpoint_sha256=(
                job.requeued_checkpoint_sha256
            ),
        )

    def _status(self, job: _ScheduledGPUJob) -> JobStatus:
        return JobStatus(
            backend_id=self.backend_id,
            job_id=job.job_id,
            spec_sha256=job.cloud_spec.sha256,
            state=job.state,
            reason=job.reason,
            checkpoint_sha256=(
                hashlib.sha256(job.checkpoint_token.encode("utf-8")).hexdigest()
                if job.checkpoint_token is not None
                else None
            ),
            network_used=job.network_used,
            scientific_evidence=False,
            validation_status=ValidationStatus.UNTESTED,
            execution_plan_sha256=job.plan.sha256,
            queue_position=job.queue_position,
            resumed_from_checkpoint_sha256=(
                job.requeued_checkpoint_sha256
            ),
        )

    def _apply_status(
        self,
        job: _ScheduledGPUJob,
        status: ScheduledGPUStatus,
        *,
        allow_attempt_increment: bool = False,
    ) -> None:
        if not isinstance(status, ScheduledGPUStatus):
            raise ExperimentError("scheduler transport returned an invalid status")
        if status.provider_job_id != job.provider_job_id:
            raise ExperimentIntegrityError("scheduler status changed provider job identity")
        if (
            status.state is not RunState.PREEMPTED
            and status.checkpoint_token is not None
        ):
            echoed_checkpoint_sha256 = hashlib.sha256(
                status.checkpoint_token.encode("utf-8")
            ).hexdigest()
            if (
                not allow_attempt_increment
                or job.pending_checkpoint_sha256 != echoed_checkpoint_sha256
            ):
                raise ExperimentIntegrityError(
                    "scheduler returned an unbound checkpoint outside PREEMPTED state"
                )
        if status.attempt < job.attempt:
            raise ExperimentIntegrityError("scheduler status regressed the attempt number")
        if allow_attempt_increment:
            if status.attempt != job.attempt + 1:
                raise ExperimentIntegrityError(
                    "scheduler requeue must advance exactly one attempt"
                )
        elif status.attempt != job.attempt:
            raise ExperimentIntegrityError("scheduler attempt changed without explicit requeue")
        if status.state not in self._ALLOWED_TRANSITIONS[job.state]:
            raise ExperimentIntegrityError(
                f"invalid scheduler transition {job.state.value}->{status.state.value}"
            )
        if (
            job.state is RunState.PREEMPTED
            and status.state in {RunState.QUEUED, RunState.RUNNING}
            and not allow_attempt_increment
        ):
            raise ExperimentIntegrityError("scheduler bypassed explicit checkpoint requeue")
        if job.state is RunState.PREEMPTED:
            if (
                job.checkpoint_token is not None
                and status.checkpoint_token not in {None, job.checkpoint_token}
            ):
                raise ExperimentIntegrityError("scheduler changed frozen checkpoint identity")
        # Provider text is untrusted and can echo checkpoint/credential-like
        # strings.  Persist and expose only a source-owned disposition code.
        job.state = status.state
        job.reason = f"SCHEDULER_{status.state.value}_UNATTESTED"
        job.queue_position = status.queue_position
        if status.checkpoint_token is not None:
            checkpoint_sha256 = hashlib.sha256(
                status.checkpoint_token.encode("utf-8")
            ).hexdigest()
            if (
                job.pending_checkpoint_sha256 is not None
                and checkpoint_sha256 != job.pending_checkpoint_sha256
            ):
                raise ExperimentIntegrityError(
                    "scheduler checkpoint differs from frozen checkpoint hash"
                )
            job.checkpoint_token = status.checkpoint_token
            if status.state is RunState.PREEMPTED:
                job.pending_checkpoint_sha256 = checkpoint_sha256
        if status.state is not RunState.PREEMPTED:
            job.checkpoint_token = None
            job.pending_checkpoint_sha256 = None
        job.attempt = status.attempt

    def _require_job_execution_authority(
        self,
        job: _ScheduledGPUJob,
    ) -> tuple[ComputeEscalationPlanAuthority, str, ScheduledGPURequest]:
        if self._registry is None or self._ledger is None:
            raise ExperimentError("scheduled GPU job has no authority runtime")
        authority = require_compute_escalation_plan_authority(
            self._registry,
            self._ledger,
            authority_artifact_sha256=job.authority_artifact_sha256,
            expected_run_id=job.authority_run_id,
            expected_decision_id=job.decision.decision_id,
        )
        request = ScheduledGPURequest(
            job.cloud_spec,
            job.plan,
            job.idempotency_key,
        )
        request_sha256 = hashlib.sha256(
            canonical_json_bytes(request.to_dict())
        ).hexdigest()
        if (
            authority.authority_id != job.authority_id
            or authority.authority_key_sha256 != job.authority_key_sha256
            or authority.local_spec_sha256 != job.local_spec.sha256
            or authority.cloud_spec_sha256 != job.cloud_spec.sha256
            or authority.project_definition_sha256
            != job.cloud_spec.project_definition_sha256
            or authority.decision_sha256 != job.decision.sha256
            or authority.submission_plan_sha256 != job.plan.sha256
            or request_sha256 != job.request_sha256
        ):
            raise ExperimentError(
                "scheduled GPU job authority differs from its frozen execution closure"
            )
        gate_sha256 = _require_compute_escalation_submission_authorization(
            self._registry,
            self._ledger,
            submission_authorization_artifact_sha256=(
                job.submission_authorization_artifact_sha256
            ),
            authority_artifact_sha256=job.authority_artifact_sha256,
            authority_run_id=job.authority_run_id,
            authority=authority,
            local_spec=job.local_spec,
            cloud_spec=job.cloud_spec,
            decision=job.decision,
            plan=job.plan,
            request=request,
        )
        if gate_sha256 != job.gate_authorization_sha256:
            raise ExperimentError(
                "scheduled GPU gate authorization differs from its frozen replay"
            )
        return authority, gate_sha256, request

    def _recover_consumed_submission_authorization(
        self,
        *,
        authority_artifact_sha256: str,
        request: ScheduledGPURequest,
        action_idempotency_key: str,
    ) -> str | None:
        """Reopen the auth named by an exact consumed-but-unpersisted submit."""

        if self._ledger is None:
            raise ExperimentError("scheduled GPU job has no authority ledger")
        request_sha256 = hashlib.sha256(
            canonical_json_bytes(request.to_dict())
        ).hexdigest()
        candidates: list[Mapping[str, Any]] = []
        for event in self._ledger.events():
            consumption = thaw_json(event.metadata).get(
                "compute_escalation_submission_consumption"
            )
            if (
                isinstance(consumption, Mapping)
                and consumption.get("schema_version")
                == COMPUTE_ESCALATION_SUBMISSION_CONSUMPTION_SCHEMA
                and consumption.get("action_type") == "SUBMIT"
                and consumption.get("authority_artifact_sha256")
                == authority_artifact_sha256
                and consumption.get("idempotency_key")
                == request.idempotency_key
                and consumption.get("request_sha256") == request_sha256
                and consumption.get("action_idempotency_key")
                == action_idempotency_key
            ):
                candidates.append(consumption)
        if not candidates:
            return None
        if len(candidates) != 1:
            raise SubmissionConflictError(
                "compute escalation submit recovery is ambiguous"
            )
        authorization_sha256 = candidates[0].get(
            "submission_authorization_artifact_sha256"
        )
        try:
            validate_sha256(
                authorization_sha256,
                "recovered compute escalation submission authorization SHA-256",
            )
        except ValidationError as exc:
            raise ExperimentError(
                "consumed compute escalation submission authorization is malformed"
            ) from exc
        assert isinstance(authorization_sha256, str)
        return authorization_sha256

    @staticmethod
    def _attempt_consumption_binding(
        *,
        authority: ComputeEscalationPlanAuthority,
        authority_artifact_sha256: str,
        authority_run_id: str,
        submission_authorization_artifact_sha256: str,
        gate_authorization_sha256: str,
        request: ScheduledGPURequest,
        local_spec: FrozenRunSpec,
        cloud_spec: FrozenRunSpec,
        decision: EscalationDecision,
        action_type: str,
        provider_job_id: str | None,
        checkpoint_sha256: str | None,
        preemption_snapshot_sha256: str | None,
        source_attempt: int,
        target_attempt: int,
        action_idempotency_key: str,
    ) -> dict[str, Any]:
        """Return the one exact source-owned paid-action binding."""

        cumulative_monetary_cost = (
            authority.expected_monetary_cost * target_attempt
        )
        cumulative_wall_clock_seconds = (
            authority.expected_wall_clock_seconds * target_attempt
        )
        request_sha256 = hashlib.sha256(
            canonical_json_bytes(request.to_dict())
        ).hexdigest()
        return {
            "schema_version": COMPUTE_ESCALATION_SUBMISSION_CONSUMPTION_SCHEMA,
            "action_type": action_type,
            "authority_artifact_sha256": authority_artifact_sha256,
            "authority_id": authority.authority_id,
            "authority_key_sha256": authority.authority_key_sha256,
            "run_id": authority_run_id,
            "local_spec_sha256": local_spec.sha256,
            "cloud_spec_sha256": cloud_spec.sha256,
            "project_definition_sha256": cloud_spec.project_definition_sha256,
            "submission_plan_sha256": request.submission_plan.sha256,
            "decision_sha256": decision.sha256,
            "human_gate_policy_artifact_sha256": (
                authority.human_gate_policy_artifact_sha256
            ),
            "human_gate_policy_sha256": authority.human_gate_policy_sha256,
            "budget_artifact_sha256": authority.budget_artifact_sha256,
            "budget_sha256": authority.budget_sha256,
            "expected_monetary_cost": authority.expected_monetary_cost,
            "maximum_monetary_cost": authority.maximum_monetary_cost,
            "expected_wall_clock_seconds": authority.expected_wall_clock_seconds,
            "maximum_total_attempts": authority.maximum_total_attempts,
            "maximum_cumulative_monetary_cost": (
                authority.maximum_cumulative_monetary_cost
            ),
            "maximum_cumulative_wall_clock_seconds": (
                authority.maximum_cumulative_wall_clock_seconds
            ),
            "provider_job_id": provider_job_id,
            "checkpoint_sha256": checkpoint_sha256,
            "preemption_snapshot_sha256": preemption_snapshot_sha256,
            "source_attempt": source_attempt,
            "target_attempt": target_attempt,
            "cumulative_monetary_cost": cumulative_monetary_cost,
            "remaining_monetary_cost": (
                authority.maximum_cumulative_monetary_cost
                - cumulative_monetary_cost
            ),
            "cumulative_wall_clock_seconds": cumulative_wall_clock_seconds,
            "remaining_wall_clock_seconds": (
                authority.maximum_cumulative_wall_clock_seconds
                - cumulative_wall_clock_seconds
            ),
            "submission_authorization_artifact_sha256": (
                submission_authorization_artifact_sha256
            ),
            "gate_authorization_sha256": gate_authorization_sha256,
            "authority_ledger_event_id": authority.ledger_event_id,
            "authority_ledger_event_hash": authority.ledger_event_hash,
            "idempotency_key": request.idempotency_key,
            "request_sha256": request_sha256,
            "action_idempotency_key": action_idempotency_key,
        }

    @staticmethod
    def _require_unconsumed_submit_work(
        events: tuple[LedgerEvent, ...],
        *,
        action_type: str,
        cloud_spec_sha256: str,
        authority_artifact_sha256: str,
    ) -> None:
        """A renamed plan cannot purchase an already consumed exact spec.

        Same-authority recovery and requeue retain their existing exact
        consumption checks. Corrections do not erase a prior paid intent:
        an unknown transport outcome is not evidence that no work occurred.
        Distinct frozen specs remain independent, even with a shared budget.
        """
        if action_type != "SUBMIT":
            return
        for event in events:
            consumption = thaw_json(event.metadata).get(
                "compute_escalation_submission_consumption"
            )
            if (
                isinstance(consumption, Mapping)
                and consumption.get("action_type") == "SUBMIT"
                and consumption.get("cloud_spec_sha256") == cloud_spec_sha256
                and consumption.get("authority_artifact_sha256")
                != authority_artifact_sha256
            ):
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU exact work was already consumed under another authority"
                )

    def _consume_attempt_authority(
        self,
        *,
        authority: ComputeEscalationPlanAuthority,
        authority_artifact_sha256: str,
        authority_run_id: str,
        submission_authorization_artifact_sha256: str,
        gate_authorization_sha256: str,
        request: ScheduledGPURequest,
        local_spec: FrozenRunSpec,
        cloud_spec: FrozenRunSpec,
        decision: EscalationDecision,
        action_type: str,
        provider_job_id: str | None,
        checkpoint_sha256: str | None,
        preemption_snapshot_sha256: str | None,
        preemption_snapshot_event_id: str | None,
        recovery_job_id: str,
        source_attempt: int,
        target_attempt: int,
        action_idempotency_key: str,
        require_fresh_authority_head: bool,
        allow_exact_recovery: bool = False,
    ) -> LedgerEvent:
        if self._registry is None or self._ledger is None:
            raise ExperimentError("scheduled GPU job has no authority ledger")
        validate_identifier(recovery_job_id, "scheduled GPU recovery job ID")
        if action_type not in {"SUBMIT", "REQUEUE"}:
            raise ExperimentError("unknown scheduled GPU authority action")
        validate_identifier(action_idempotency_key, "GPU authority action key")
        if provider_job_id is not None:
            provider_job_id = _opaque_reference(
                provider_job_id,
                "provider GPU job ID",
            )
        if checkpoint_sha256 is not None:
            validate_sha256(checkpoint_sha256, "GPU requeue checkpoint SHA-256")
        if preemption_snapshot_sha256 is not None:
            validate_sha256(
                preemption_snapshot_sha256,
                "GPU preemption recovery snapshot SHA-256",
            )
        if preemption_snapshot_event_id is not None:
            validate_identifier(
                preemption_snapshot_event_id,
                "GPU preemption recovery snapshot event ID",
            )
        if (
            isinstance(source_attempt, bool)
            or isinstance(target_attempt, bool)
            or not isinstance(source_attempt, int)
            or not isinstance(target_attempt, int)
            or source_attempt < 0
            or target_attempt != source_attempt + 1
            or target_attempt > authority.maximum_total_attempts
        ):
            raise ExperimentError("scheduled GPU attempt exceeds its frozen ceiling")
        if action_type == "SUBMIT" and (
            provider_job_id is not None
            or checkpoint_sha256 is not None
            or preemption_snapshot_sha256 is not None
            or preemption_snapshot_event_id is not None
            or source_attempt != 0
            or target_attempt != 1
        ):
            raise ExperimentError("initial GPU consumption has invalid attempt lineage")
        if action_type == "REQUEUE" and (
            provider_job_id is None
            or checkpoint_sha256 is None
            or preemption_snapshot_sha256 is None
            or preemption_snapshot_event_id is None
            or source_attempt < 1
        ):
            raise ExperimentError("GPU requeue consumption lacks exact lineage")
        cumulative_monetary_cost = (
            authority.expected_monetary_cost * target_attempt
        )
        cumulative_wall_clock_seconds = (
            authority.expected_wall_clock_seconds * target_attempt
        )
        if (
            cumulative_monetary_cost
            > authority.maximum_cumulative_monetary_cost
            or cumulative_wall_clock_seconds
            > authority.maximum_cumulative_wall_clock_seconds
        ):
            raise ExperimentError("scheduled GPU cumulative budget is exhausted")
        request_sha256 = hashlib.sha256(
            canonical_json_bytes(request.to_dict())
        ).hexdigest()
        events = self._ledger.events()
        if not events or events[-1].event_hash is None:
            raise ExperimentError("compute escalation ledger has no live head")
        self._require_unconsumed_submit_work(
            events,
            action_type=action_type,
            cloud_spec_sha256=cloud_spec.sha256,
            authority_artifact_sha256=authority_artifact_sha256,
        )
        prior_consumptions: list[tuple[LedgerEvent, Mapping[str, Any]]] = []
        for event in events:
            consumption = thaw_json(event.metadata).get(
                "compute_escalation_submission_consumption"
            )
            if (
                isinstance(consumption, Mapping)
                and consumption.get("authority_artifact_sha256")
                == authority_artifact_sha256
            ):
                prior_consumptions.append((event, consumption))
        prior_event_ids = {event.event_id for event, _ in prior_consumptions}
        if any(
            event.event_type == "CORRECTION"
            and event.supersedes_event_id in prior_event_ids
            for event in events
        ):
            raise ExperimentError(
                "compute escalation attempt consumption was corrected"
            )
        consumption_binding = self._attempt_consumption_binding(
            authority=authority,
            authority_artifact_sha256=authority_artifact_sha256,
            authority_run_id=authority_run_id,
            submission_authorization_artifact_sha256=(
                submission_authorization_artifact_sha256
            ),
            gate_authorization_sha256=gate_authorization_sha256,
            request=request,
            local_spec=local_spec,
            cloud_spec=cloud_spec,
            decision=decision,
            action_type=action_type,
            provider_job_id=provider_job_id,
            checkpoint_sha256=checkpoint_sha256,
            preemption_snapshot_sha256=preemption_snapshot_sha256,
            source_attempt=source_attempt,
            target_attempt=target_attempt,
            action_idempotency_key=action_idempotency_key,
        )
        exact_replay: LedgerEvent | None = None
        for event, consumption in prior_consumptions:
            if (
                consumption.get("schema_version")
                != COMPUTE_ESCALATION_SUBMISSION_CONSUMPTION_SCHEMA
                or consumption.get("action_idempotency_key")
                == action_idempotency_key
                or consumption.get("target_attempt") == target_attempt
                or (
                    action_type == "SUBMIT"
                    and consumption.get("action_type") == "SUBMIT"
                )
            ):
                if dict(consumption) == consumption_binding:
                    if exact_replay is not None:
                        raise SubmissionConflictError(
                            "compute escalation attempt recovery is ambiguous"
                        )
                    exact_replay = event
                    continue
                raise SubmissionConflictError(
                    "compute escalation attempt authority was already consumed"
                )
        if exact_replay is not None:
            if not allow_exact_recovery:
                raise SubmissionConflictError(
                    "compute escalation attempt authority was already consumed"
                )
            if events[-1].event_id != exact_replay.event_id:
                raise ExperimentError(
                    "compute escalation attempt recovery is not ledger-adjacent"
                )
            return exact_replay
        if require_fresh_authority_head and (
            events[-1].event_id != authority.ledger_event_id
            or events[-1].event_hash != authority.ledger_event_hash
        ):
            raise ExperimentError(
                "compute escalation authority is not the fresh ledger head"
            )
        # The preliminary replay above gives deterministic diagnostics.  The
        # authoritative consume decision is repeated while the registry and
        # ledger are co-locked, so another backend cannot advance this job
        # between validating its durable precondition and consuming an attempt.
        registry_guard = self._registry._open_mutation_lock()
        try:
            ledger_guard = self._ledger._open_lock()
            try:
                self._registry._verify_all_locked(
                    registry_guard, raise_on_error=True
                )
                locked_result = self._ledger._validate_bytes(
                    self._ledger._read_raw_locked(ledger_guard)
                )
                if not locked_result.valid or not locked_result.events:
                    raise ExperimentIntegrityError(
                        "compute escalation ledger is invalid during consumption"
                    )
                locked_events = locked_result.events
                self._require_unconsumed_submit_work(
                    locked_events,
                    action_type=action_type,
                    cloud_spec_sha256=cloud_spec.sha256,
                    authority_artifact_sha256=authority_artifact_sha256,
                )
                locked_consumptions: list[
                    tuple[LedgerEvent, Mapping[str, Any]]
                ] = []
                for candidate in locked_events:
                    consumption = thaw_json(candidate.metadata).get(
                        "compute_escalation_submission_consumption"
                    )
                    if (
                        isinstance(consumption, Mapping)
                        and consumption.get("authority_artifact_sha256")
                        == authority_artifact_sha256
                    ):
                        locked_consumptions.append((candidate, consumption))
                locked_consumption_ids = {
                    candidate.event_id for candidate, _ in locked_consumptions
                }
                if any(
                    candidate.event_type == "CORRECTION"
                    and candidate.supersedes_event_id in locked_consumption_ids
                    for candidate in locked_events
                ):
                    raise ExperimentError(
                        "compute escalation attempt consumption was corrected"
                    )
                locked_exact: LedgerEvent | None = None
                for candidate, consumption in locked_consumptions:
                    if (
                        consumption.get("schema_version")
                        != COMPUTE_ESCALATION_SUBMISSION_CONSUMPTION_SCHEMA
                        or consumption.get("action_idempotency_key")
                        == action_idempotency_key
                        or consumption.get("target_attempt") == target_attempt
                        or (
                            action_type == "SUBMIT"
                            and consumption.get("action_type") == "SUBMIT"
                        )
                    ):
                        if dict(consumption) == consumption_binding:
                            if locked_exact is not None:
                                raise SubmissionConflictError(
                                    "compute escalation attempt recovery is ambiguous"
                                )
                            locked_exact = candidate
                            continue
                        raise SubmissionConflictError(
                            "compute escalation attempt authority was already consumed"
                        )
                if locked_exact is not None:
                    if not allow_exact_recovery:
                        raise SubmissionConflictError(
                            "compute escalation attempt authority was already consumed"
                        )
                    if locked_events[-1].event_id != locked_exact.event_id:
                        raise ExperimentError(
                            "compute escalation attempt recovery is not ledger-adjacent"
                        )
                    return locked_exact
                if require_fresh_authority_head and (
                    locked_events[-1].event_id != authority.ledger_event_id
                    or locked_events[-1].event_hash != authority.ledger_event_hash
                ):
                    raise ExperimentError(
                        "compute escalation authority is not the fresh ledger head"
                    )
                admitted = [
                    candidate
                    for candidate in locked_events
                    if isinstance(
                        thaw_json(candidate.metadata).get(
                            "scheduled_gpu_recovery_snapshot"
                        ),
                        Mapping,
                    )
                    and thaw_json(candidate.metadata)[
                        "scheduled_gpu_recovery_snapshot"
                    ].get("job_id")
                    == recovery_job_id
                ]
                if (
                    len(admitted) + 1
                    > _MAX_SCHEDULED_GPU_SNAPSHOTS_PER_JOB
                ):
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU response snapshot capacity is exhausted"
                    )
                if action_type == "SUBMIT" and admitted:
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU submit already has a recovery source"
                    )
                if action_type == "REQUEUE":
                    if not admitted:
                        raise ScheduledGPURecoveryBlocked(
                            "scheduled GPU requeue has no durable preemption head"
                        )
                    latest_event = admitted[-1]
                    latest_marker = thaw_json(latest_event.metadata)[
                        "scheduled_gpu_recovery_snapshot"
                    ]
                    if (
                        latest_event.event_id != preemption_snapshot_event_id
                        or latest_marker.get("snapshot_sha256")
                        != preemption_snapshot_sha256
                        or latest_marker.get("state") != RunState.PREEMPTED.value
                        or latest_marker.get("attempt") != source_attempt
                        or latest_marker.get("pending_action_key") is not None
                        or any(
                            candidate.event_type == "CORRECTION"
                            and candidate.supersedes_event_id
                            == latest_event.event_id
                            for candidate in locked_events
                        )
                    ):
                        raise ScheduledGPURecoveryBlocked(
                            "scheduled GPU preemption head changed before requeue"
                        )
                    resolved_ids = {
                        thaw_json(candidate.metadata)[
                            "scheduled_gpu_recovery_snapshot"
                        ].get("causal_consumption_event_id")
                        for candidate in admitted
                    }
                    if any(
                        candidate.event_id not in resolved_ids
                        and consumption.get("request_sha256") == request_sha256
                        for candidate, consumption in locked_consumptions
                    ):
                        raise ScheduledGPURecoveryBlocked(
                            "scheduled GPU job already has an unresolved action"
                        )
                prior_event_hash = locked_result.head_hash
                assert prior_event_hash is not None
                pending_event = LedgerEvent.create(
                    run_id=authority_run_id,
                    actor_role=Role.EXPERIMENT_RUNNER,
                    state_before=locked_events[-1].state_after,
                    requested_state_after=locked_events[-1].state_after,
                    artifact_hashes=(
                        authority_artifact_sha256,
                        submission_authorization_artifact_sha256,
                        *authority.input_artifact_hashes,
                    ),
                    code_version=f"sha256:{cloud_spec.code_sha256}",
                    configuration_hash=cloud_spec.configuration_sha256,
                    dataset_identifiers=(cloud_spec.data_sha256,),
                    random_seeds=cloud_spec.seeds,
                    evaluator_outputs=(),
                    reason=(
                        "consumed one exact compute-escalation attempt authority "
                        f"immediately before scheduled GPU {action_type.lower()}"
                    ),
                    event_type="CHECKPOINT",
                    metadata={
                        "compute_escalation_submission_consumption": (
                            consumption_binding
                        )
                    },
                    prior_event_hash=prior_event_hash,
                )

                def build(current: Any) -> LedgerEvent:
                    if current != locked_result:
                        raise ScheduledGPURecoveryBlocked(
                            "compute escalation ledger changed during consumption"
                        )
                    return pending_event

                committed = self._ledger._append_locked(ledger_guard, build)
                if (
                    committed.prior_event_hash != prior_event_hash
                    or committed.event_hash is None
                ):
                    raise ExperimentError(
                        "compute escalation attempt was not consumed adjacently"
                    )
                return committed
            finally:
                self._ledger._unlock(ledger_guard)
        finally:
            self._registry._unlock_mutation(registry_guard)

    def _recovery_snapshot_value(self, job: _ScheduledGPUJob) -> dict[str, Any]:
        """Return canonical, secret-free process-recovery state.

        Scheduler messages are not provenance.  In particular, provider
        reasons and checkpoint tokens are volatile: providers are allowed to
        echo credentials/checkpoint material in either field.
        """
        return {
            "schema_version": _SCHEDULED_GPU_RECOVERY_SCHEMA,
            "backend_id": self.backend_id,
            "provider_name": self.provider_name,
            "job_id": job.job_id,
            "provider_job_id": job.provider_job_id,
            "idempotency_key": job.idempotency_key,
            "state": job.state.value,
            "attempt": job.attempt,
            "network_used": job.network_used,
            "validation_status": ValidationStatus.UNTESTED.value,
            "scientific_evidence": False,
            "local_spec": job.local_spec.to_dict(),
            "cloud_spec": job.cloud_spec.to_dict(),
            "decision": job.decision.to_dict(),
            "plan": job.plan.to_dict(),
            "authority_artifact_sha256": job.authority_artifact_sha256,
            "authority_run_id": job.authority_run_id,
            "authority_id": job.authority_id,
            "authority_key_sha256": job.authority_key_sha256,
            "submission_authorization_artifact_sha256": (
                job.submission_authorization_artifact_sha256
            ),
            "gate_authorization_sha256": job.gate_authorization_sha256,
            "request_sha256": job.request_sha256,
            "pending_checkpoint_sha256": job.pending_checkpoint_sha256,
            "requeued_checkpoint_sha256": job.requeued_checkpoint_sha256,
            "requeued_from_attempt": job.requeued_from_attempt,
            "requeue_history": [item.to_dict() for item in job.requeue_history],
            "queue_position": job.queue_position,
            "prior_snapshot_sha256": job.snapshot_sha256,
            "prior_snapshot_event_id": job.snapshot_event_id,
            "pending_action_key": job.pending_action_key,
            "causal_consumption_action_key": job.causal_consumption_action_key,
            "causal_consumption_event_id": job.causal_consumption_event_id,
            "causal_consumption_event_hash": job.causal_consumption_event_hash,
            "collected_manifest_sha256": job.collected_manifest_sha256,
            "collected_artifact_sha256s": list(job.collected_artifact_sha256s),
            "collected_bundle_sha256": job.collected_bundle_sha256,
        }

    def _preflight_recovery_capacity(
        self,
        *,
        job_id: str,
        required_snapshots: int,
    ) -> None:
        """Fail before a transport call when a response cannot be admitted."""
        if self._registry is None or self._ledger is None:
            raise ExperimentError("scheduled GPU job has no authority ledger")
        validate_identifier(job_id, "scheduled GPU recovery job ID")
        if required_snapshots not in {1, 2}:
            raise ExperimentError("scheduled GPU recovery capacity request is invalid")
        # Keep this import local to this backend-only persistence seam.
        from .artifacts import MAX_REGISTRY_RECORDS
        from .ledger import MAX_LEDGER_BYTES, MAX_LEDGER_EVENTS

        registry_guard = self._registry._open_mutation_lock()
        try:
            ledger_guard = self._ledger._open_lock()
            try:
                registry_result = self._registry._verify_all_locked(
                    registry_guard,
                    raise_on_error=True,
                )
                result = self._ledger._validate_bytes(
                    self._ledger._read_raw_locked(ledger_guard)
                )
                if not result.valid:
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU recovery ledger is invalid"
                    )
                admitted_count = sum(
                    1
                    for event in result.events
                    if isinstance(
                        thaw_json(event.metadata).get(
                            "scheduled_gpu_recovery_snapshot"
                        ),
                        Mapping,
                    )
                    and thaw_json(event.metadata)[
                        "scheduled_gpu_recovery_snapshot"
                    ].get("job_id")
                    == job_id
                )
                # One consumption plus one response, or a cancel intent plus
                # its response, fits this conservative global allowance.  The
                # exact append still enforces the hard byte/count limits.
                if (
                    admitted_count + required_snapshots
                    > _MAX_SCHEDULED_GPU_SNAPSHOTS_PER_JOB
                    or result.event_count + 2 > MAX_LEDGER_EVENTS
                    or result.valid_prefix_bytes + 192 * 1024
                    > MAX_LEDGER_BYTES
                    or registry_result.count + required_snapshots
                    > MAX_REGISTRY_RECORDS
                ):
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU response capacity is unavailable before transport"
                    )
            finally:
                self._ledger._unlock(ledger_guard)
        finally:
            self._registry._unlock_mutation(registry_guard)

    def _consumption_action_exists(self, action_key: str) -> bool:
        if self._ledger is None:
            return False
        return any(
            isinstance(
                thaw_json(event.metadata).get(
                    "compute_escalation_submission_consumption"
                ),
                Mapping,
            )
            and thaw_json(event.metadata)["compute_escalation_submission_consumption"].get(
                "action_idempotency_key"
            ) == action_key
            for event in self._ledger.events()
        )

    def _persist_recovery_snapshot(
        self,
        job: _ScheduledGPUJob,
        *,
        required_successor_snapshots: int = 0,
    ) -> None:
        """Registry-first, ledger-second durable admission of one job state."""
        if self._registry is None or self._ledger is None:
            return
        if required_successor_snapshots not in {0, 1}:
            raise ExperimentError("scheduled GPU successor capacity is invalid")
        value = self._recovery_snapshot_value(job)
        snapshot_bytes = canonical_json_bytes(value)
        snapshot_sha256 = hashlib.sha256(snapshot_bytes).hexdigest()
        no_change = False
        if job.snapshot_sha256 is not None:
            try:
                previous = safe_json_loads(self._registry.get_bytes(job.snapshot_sha256))
            except (ArtifactError, ValidationError) as exc:
                raise ExperimentIntegrityError("scheduled GPU prior recovery snapshot is unavailable") from exc
            if isinstance(previous, Mapping):
                prior_comparable = dict(previous)
                current_comparable = dict(value)
                for item in ("prior_snapshot_sha256", "prior_snapshot_event_id"):
                    prior_comparable.pop(item, None)
                    current_comparable.pop(item, None)
                if prior_comparable == current_comparable:
                    no_change = True

        registry_guard = self._registry._open_mutation_lock()
        try:
            ledger_guard = self._ledger._open_lock()
            try:
                self._registry._verify_all_locked(
                    registry_guard, raise_on_error=True
                )
                ledger_result = self._ledger._validate_bytes(
                    self._ledger._read_raw_locked(ledger_guard)
                )
                if not ledger_result.valid or not ledger_result.events:
                    raise ExperimentIntegrityError("scheduled GPU recovery ledger is invalid")
                # The shared ledger may legitimately contain unrelated jobs
                # and subsystems after this job's prior checkpoint.  Select
                # only this job's latest admitted head, then append against
                # the current global head under the same co-lock.
                admitted = [
                    item for item in ledger_result.events
                    if isinstance(
                        thaw_json(item.metadata).get(
                            "scheduled_gpu_recovery_snapshot"
                        ),
                        Mapping,
                    )
                    and thaw_json(item.metadata)[
                        "scheduled_gpu_recovery_snapshot"
                    ].get("job_id") == job.job_id
                ]
                protected_event_ids = {
                    *(item.event_id for item in admitted),
                    *(
                        (job.causal_consumption_event_id,)
                        if job.causal_consumption_event_id is not None
                        else ()
                    ),
                }
                if any(
                    item.event_type == "CORRECTION"
                    and item.supersedes_event_id in protected_event_ids
                    for item in ledger_result.events
                ):
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU recovery source was corrected"
                    )
                if job.snapshot_event_id is None:
                    if admitted:
                        raise ScheduledGPURecoveryBlocked(
                            "scheduled GPU recovery source already has a head"
                        )
                elif (
                    not admitted
                    or admitted[-1].event_id != job.snapshot_event_id
                    or thaw_json(admitted[-1].metadata)[
                        "scheduled_gpu_recovery_snapshot"
                    ].get("snapshot_sha256") != job.snapshot_sha256
                ):
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU recovery source changed; reconciliation required"
                    )
                if not no_change and (
                    len(admitted) + 1 + required_successor_snapshots
                    > _MAX_SCHEDULED_GPU_SNAPSHOTS_PER_JOB
                ):
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU recovery snapshot ceiling is exhausted"
                    )
                resolved_consumption_ids = {
                    thaw_json(item.metadata)[
                        "scheduled_gpu_recovery_snapshot"
                    ].get("causal_consumption_event_id")
                    for item in admitted
                }
                relevant_consumptions: list[
                    tuple[LedgerEvent, Mapping[str, Any]]
                ] = []
                for item in ledger_result.events:
                    consumption = thaw_json(item.metadata).get(
                        "compute_escalation_submission_consumption"
                    )
                    if (
                        isinstance(consumption, Mapping)
                        and consumption.get("authority_artifact_sha256")
                        == job.authority_artifact_sha256
                        and consumption.get("request_sha256")
                        == job.request_sha256
                    ):
                        relevant_consumptions.append((item, consumption))
                relevant_ids = {item.event_id for item, _ in relevant_consumptions}
                if any(
                    item.event_type == "CORRECTION"
                    and item.supersedes_event_id in relevant_ids
                    for item in ledger_result.events
                ):
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU attempt consumption was corrected"
                    )
                unresolved = [
                    (item, consumption)
                    for item, consumption in relevant_consumptions
                    if item.event_id not in resolved_consumption_ids
                ]
                if len(unresolved) > 1:
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU job has ambiguous unresolved actions"
                    )
                if unresolved:
                    unresolved_event, unresolved_value = unresolved[0]
                    unresolved_key = unresolved_value.get("action_idempotency_key")
                    resolves_response = (
                        job.pending_action_key is None
                        and job.causal_consumption_action_key == unresolved_key
                        and job.causal_consumption_event_id
                        == unresolved_event.event_id
                        and job.causal_consumption_event_hash
                        == unresolved_event.event_hash
                    )
                    preserves_pending = job.pending_action_key == unresolved_key
                    if not (resolves_response or preserves_pending):
                        raise ScheduledGPURecoveryBlocked(
                            "scheduled GPU unresolved action differs from response"
                        )
                elif (
                    job.pending_action_key is not None
                    and not job.pending_action_key.startswith("cancel-")
                ):
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU pending action lacks a durable intent"
                    )
                if no_change:
                    return
                parents = tuple(
                    dict.fromkeys(
                        (
                            job.authority_artifact_sha256,
                            job.submission_authorization_artifact_sha256,
                            *((job.snapshot_sha256,) if job.snapshot_sha256 else ()),
                        )
                    )
                )
                record = self._registry._put_bytes_locked(
                    registry_guard,
                    snapshot_bytes,
                    logical_type=_SCHEDULED_GPU_RECOVERY_LOGICAL_TYPE,
                    origin="source-owned scheduled GPU process recovery snapshot",
                    creator_role=Role.EXPERIMENT_RUNNER,
                    creation_command=_SCHEDULED_GPU_RECOVERY_COMMAND,
                    parent_artifacts=parents,
                    schema_version="1.0",
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                    created_at=None,
                )
                # The registry can contain an inert orphan after a power loss;
                # it gains no effect until this exact event is appended.
                event = LedgerEvent.create(
                    run_id=job.authority_run_id,
                    actor_role=Role.EXPERIMENT_RUNNER,
                    state_before=ledger_result.events[-1].requested_state_after,
                    requested_state_after=ledger_result.events[-1].requested_state_after,
                    artifact_hashes=(record.sha256, *parents),
                    code_version=f"sha256:{job.cloud_spec.code_sha256}",
                    configuration_hash=job.cloud_spec.configuration_sha256,
                    dataset_identifiers=(job.cloud_spec.data_sha256,),
                    random_seeds=job.cloud_spec.seeds,
                    evaluator_outputs=(),
                    reason="durably admitted scheduled GPU recovery snapshot",
                    event_type="CHECKPOINT",
                    metadata={
                        "scheduled_gpu_recovery_snapshot": {
                            "schema_version": _SCHEDULED_GPU_RECOVERY_SCHEMA,
                            "snapshot_sha256": record.sha256,
                            "job_id": job.job_id,
                            "provider_job_id": job.provider_job_id,
                            "state": job.state.value,
                            "attempt": job.attempt,
                            "prior_snapshot_sha256": job.snapshot_sha256,
                            "prior_snapshot_event_id": job.snapshot_event_id,
                            "pending_action_key": job.pending_action_key,
                            "causal_consumption_action_key": job.causal_consumption_action_key,
                            "causal_consumption_event_id": job.causal_consumption_event_id,
                            "causal_consumption_event_hash": job.causal_consumption_event_hash,
                        }
                    },
                    prior_event_hash=ledger_result.head_hash,
                )
                def build(current: Any) -> LedgerEvent:
                    if current != ledger_result:
                        raise ScheduledGPURecoveryBlocked(
                            "scheduled GPU recovery ledger changed during admission"
                        )
                    return event
                appended = self._ledger._append_locked(ledger_guard, build)
                if appended != event:
                    raise ExperimentIntegrityError("scheduled GPU recovery event changed")
                self._registry._verify_mutation_namespace(registry_guard)
            finally:
                self._ledger._unlock(ledger_guard)
        finally:
            self._registry._unlock_mutation(registry_guard)
        job.snapshot_sha256 = snapshot_sha256
        job.snapshot_event_id = event.event_id

    @classmethod
    def _require_recovery_successor(
        cls,
        previous: _ScheduledGPUJob | None,
        current: _ScheduledGPUJob,
        causal_consumption: Mapping[str, Any],
    ) -> None:
        """Validate immutable closure and the complete per-job state machine."""

        if current.attempt != 1 + len(current.requeue_history):
            raise ScheduledGPURecoveryBlocked(
                "scheduled GPU attempt differs from ordered requeue lineage"
            )
        for index, lineage in enumerate(current.requeue_history, start=1):
            if lineage.source_attempt != index or lineage.target_attempt != index + 1:
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU requeue lineage is not contiguous"
                )
        if current.state is RunState.PREEMPTED:
            if current.pending_checkpoint_sha256 is None:
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU PREEMPTED snapshot lacks checkpoint identity"
                )
        elif current.pending_checkpoint_sha256 is not None:
            raise ScheduledGPURecoveryBlocked(
                "scheduled GPU checkpoint identity escaped PREEMPTED state"
            )
        if current.requeue_history:
            tail = current.requeue_history[-1]
            if (
                current.requeued_from_attempt != tail.source_attempt
                or current.requeued_checkpoint_sha256 != tail.checkpoint_sha256
            ):
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU resumed checkpoint differs from requeue lineage"
                )
        elif (
            current.requeued_from_attempt is not None
            or current.requeued_checkpoint_sha256 is not None
        ):
            raise ScheduledGPURecoveryBlocked(
                "scheduled GPU resumed checkpoint lacks requeue lineage"
            )
        collection_fields_present = (
            current.collected_manifest_sha256 is not None,
            current.collected_bundle_sha256 is not None,
        )
        if collection_fields_present[0] != collection_fields_present[1]:
            raise ScheduledGPURecoveryBlocked(
                "scheduled GPU collected identity is only partially bound"
            )
        if current.collected_bundle_sha256 is not None and current.state not in {
            RunState.SUCCEEDED,
            RunState.INVALID_OUTPUT,
        }:
            raise ScheduledGPURecoveryBlocked(
                "scheduled GPU collected identity has an invalid state"
            )
        if (
            current.collected_artifact_sha256s
            and current.collected_bundle_sha256 is None
        ):
            raise ScheduledGPURecoveryBlocked(
                "scheduled GPU collected artifacts lack a bundle identity"
            )
        if previous is None:
            if (
                current.attempt != 1
                or current.requeue_history
                or current.state not in cls._ALLOWED_TRANSITIONS[RunState.SUBMITTED]
                or causal_consumption.get("action_type") != "SUBMIT"
                or current.causal_consumption_action_key
                != f"submit-{current.request_sha256[:24]}"
                or causal_consumption.get("provider_job_id") is not None
                or causal_consumption.get("checkpoint_sha256") is not None
                or causal_consumption.get("preemption_snapshot_sha256") is not None
                or causal_consumption.get("source_attempt") != 0
                or causal_consumption.get("target_attempt") != 1
            ):
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU root snapshot lacks initial submit lineage"
                )
            return

        immutable_previous = (
            previous.local_spec.sha256,
            previous.cloud_spec.sha256,
            previous.decision.sha256,
            previous.plan.sha256,
            previous.idempotency_key,
            previous.job_id,
            previous.provider_job_id,
            previous.authority_artifact_sha256,
            previous.authority_run_id,
            previous.authority_id,
            previous.authority_key_sha256,
            previous.submission_authorization_artifact_sha256,
            previous.gate_authorization_sha256,
            previous.request_sha256,
        )
        immutable_current = (
            current.local_spec.sha256,
            current.cloud_spec.sha256,
            current.decision.sha256,
            current.plan.sha256,
            current.idempotency_key,
            current.job_id,
            current.provider_job_id,
            current.authority_artifact_sha256,
            current.authority_run_id,
            current.authority_id,
            current.authority_key_sha256,
            current.submission_authorization_artifact_sha256,
            current.gate_authorization_sha256,
            current.request_sha256,
        )
        if immutable_current != immutable_previous:
            raise ScheduledGPURecoveryBlocked(
                "scheduled GPU immutable recovery closure changed"
            )
        if previous.network_used and not current.network_used:
            raise ScheduledGPURecoveryBlocked(
                "scheduled GPU recovery regressed network-use history"
            )
        if previous.state in {
            RunState.SUCCEEDED,
            RunState.FAILED,
            RunState.CANCELLED,
            RunState.INVALID_OUTPUT,
        }:
            if not (
                current.state is previous.state
                or (
                    previous.state is RunState.SUCCEEDED
                    and current.state is RunState.INVALID_OUTPUT
                )
            ):
                raise ScheduledGPURecoveryBlocked(
                    "terminal scheduled GPU recovery state reopened"
                )
        elif current.state not in cls._ALLOWED_TRANSITIONS[previous.state]:
            raise ScheduledGPURecoveryBlocked(
                "scheduled GPU recovery transition is invalid"
            )
        history_extended = len(current.requeue_history) == len(previous.requeue_history) + 1
        if history_extended:
            if current.requeue_history[:-1] != previous.requeue_history:
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU recovery rewrote requeue history"
                )
            tail = current.requeue_history[-1]
            if (
                previous.state is not RunState.PREEMPTED
                or current.state not in {RunState.QUEUED, RunState.RUNNING}
                or tail.source_attempt != previous.attempt
                or tail.target_attempt != current.attempt
                or current.attempt != previous.attempt + 1
                or previous.pending_checkpoint_sha256 != tail.checkpoint_sha256
                or causal_consumption.get("action_type") != "REQUEUE"
                or tail.action_idempotency_key
                != current.causal_consumption_action_key
                or causal_consumption.get("provider_job_id")
                != current.provider_job_id
                or causal_consumption.get("checkpoint_sha256")
                != tail.checkpoint_sha256
                or causal_consumption.get("source_attempt") != tail.source_attempt
                or causal_consumption.get("target_attempt") != tail.target_attempt
                or causal_consumption.get("preemption_snapshot_sha256")
                != previous.snapshot_sha256
            ):
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU recovery lacks exact requeue consumption"
                )
        elif (
            current.requeue_history != previous.requeue_history
            or current.attempt != previous.attempt
        ):
            raise ScheduledGPURecoveryBlocked(
                "scheduled GPU attempt changed without one requeue"
            )
        elif (
            current.causal_consumption_action_key
            != previous.causal_consumption_action_key
            or current.causal_consumption_event_id
            != previous.causal_consumption_event_id
            or current.causal_consumption_event_hash
            != previous.causal_consumption_event_hash
        ):
            raise ScheduledGPURecoveryBlocked(
                "scheduled GPU causal consumption changed without requeue"
            )
        if previous.collected_bundle_sha256 is not None and (
            current.collected_manifest_sha256
            != previous.collected_manifest_sha256
            or current.collected_artifact_sha256s
            != previous.collected_artifact_sha256s
            or current.collected_bundle_sha256
            != previous.collected_bundle_sha256
        ):
            raise ScheduledGPURecoveryBlocked(
                "scheduled GPU recovery rewrote collected output identity"
            )

    def _restore_durable_jobs(self) -> None:
        """Replay one exact ledger-selected snapshot chain before hydrating maps."""
        assert self._registry is not None and self._ledger is not None
        registry_guard = self._registry._open_mutation_lock()
        try:
            ledger_guard = self._ledger._open_lock()
            try:
                registry_snapshot = self._registry._verify_all_locked(
                    registry_guard,
                    raise_on_error=True,
                )
                ledger_snapshot = self._ledger._validate_bytes(
                    self._ledger._read_raw_locked(ledger_guard)
                )
                if not ledger_snapshot.valid:
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU recovery ledger is invalid"
                    )
            finally:
                self._ledger._unlock(ledger_guard)
        finally:
            self._registry._unlock_mutation(registry_guard)
        events = ledger_snapshot.events
        chains: dict[str, list[tuple[LedgerEvent, Mapping[str, Any]]]] = {}
        snapshot_event_ids: set[str] = set()
        for event in events:
            event_metadata = thaw_json(event.metadata)
            marker = event_metadata.get("scheduled_gpu_recovery_snapshot")
            if not isinstance(marker, Mapping):
                continue
            if set(event_metadata) != {"scheduled_gpu_recovery_snapshot"}:
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU recovery admission metadata is not exact"
                )
            if marker.get("schema_version") != _SCHEDULED_GPU_RECOVERY_SCHEMA:
                raise ScheduledGPURecoveryBlocked("unknown scheduled GPU recovery schema")
            digest = marker.get("snapshot_sha256")
            if not isinstance(digest, str):
                raise ScheduledGPURecoveryBlocked("scheduled GPU recovery snapshot is malformed")
            validate_sha256(digest, "scheduled GPU recovery snapshot SHA-256")
            if digest not in event.artifact_hashes:
                raise ScheduledGPURecoveryBlocked("scheduled GPU snapshot lacks ledger admission")
            job_id = marker.get("job_id")
            if not isinstance(job_id, str):
                raise ScheduledGPURecoveryBlocked("scheduled GPU recovery job ID is malformed")
            chains.setdefault(job_id, []).append((event, marker))
            snapshot_event_ids.add(event.event_id)
        if any(
            event.event_type == "CORRECTION"
            and event.supersedes_event_id in snapshot_event_ids
            for event in events
        ):
            raise ScheduledGPURecoveryBlocked(
                "scheduled GPU recovery snapshot was corrected"
            )
        restored: list[_ScheduledGPUJob] = []
        seen_provider_ids: set[str] = set()
        seen_idempotency_keys: set[str] = set()
        seen_cloud_specs: set[str] = set()
        for job_id, chain in chains.items():
            if len(chain) > _MAX_SCHEDULED_GPU_SNAPSHOTS_PER_JOB:
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU recovery snapshot ceiling was exceeded"
                )
            previous_sha: str | None = None
            previous_event: str | None = None
            latest: _ScheduledGPUJob | None = None
            for event, marker in chain:
                if marker.get("prior_snapshot_sha256") != previous_sha or marker.get("prior_snapshot_event_id") != previous_event:
                    raise ScheduledGPURecoveryBlocked("scheduled GPU recovery snapshot chain fork or gap")
                digest = marker["snapshot_sha256"]
                record = self._registry.get_metadata(digest)
                snapshot_source = self._registry.get_bytes(digest)
                value = safe_json_loads(snapshot_source)
                if (
                    not isinstance(value, Mapping)
                    or set(value) != _SCHEDULED_GPU_RECOVERY_FIELDS
                    or canonical_json_bytes(value) != snapshot_source
                    or value.get("schema_version") != _SCHEDULED_GPU_RECOVERY_SCHEMA
                    or value.get("backend_id") != self.backend_id
                    or value.get("validation_status")
                    != ValidationStatus.UNTESTED.value
                    or value.get("scientific_evidence") is not False
                    or value.get("job_id") != job_id
                    or value.get("prior_snapshot_sha256") != previous_sha
                    or value.get("prior_snapshot_event_id") != previous_event
                    or value.get("provider_name") != self.provider_name
                ):
                    raise ScheduledGPURecoveryBlocked("scheduled GPU recovery snapshot differs from admission")
                try:
                    local = _parse_frozen_run_spec(value["local_spec"])
                    cloud = _parse_frozen_run_spec(value["cloud_spec"])
                    decision = _parse_escalation_decision(value["decision"])
                    plan = _parse_submission_plan(value["plan"])
                    state = RunState(value["state"])
                    history = tuple(GPURequeueLineage(**item) for item in value["requeue_history"])
                except (KeyError, TypeError, ValueError, ValidationError, ExperimentError) as exc:
                    raise ScheduledGPURecoveryBlocked("scheduled GPU recovery snapshot payload is invalid") from exc
                try:
                    validate_identifier(job_id, "scheduled GPU recovery job ID")
                    validate_identifier(
                        value["authority_run_id"],
                        "scheduled GPU authority run ID",
                    )
                    validate_identifier(
                        value["authority_id"],
                        "scheduled GPU authority ID",
                    )
                    for name in (
                        "authority_artifact_sha256",
                        "authority_key_sha256",
                        "submission_authorization_artifact_sha256",
                        "gate_authorization_sha256",
                        "request_sha256",
                    ):
                        validate_sha256(value[name], f"scheduled GPU {name}")
                    validate_identifier(
                        value["idempotency_key"],
                        "scheduled GPU idempotency key",
                    )
                    _opaque_reference(
                        value["provider_job_id"],
                        "provider GPU job ID",
                    )
                except (KeyError, TypeError, ValidationError, ExperimentError) as exc:
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU recovery identity is malformed"
                    ) from exc
                if job_id != f"scheduled-gpu-{plan.sha256[:20]}":
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU recovery job ID differs from its frozen plan"
                    )
                if (
                    plan.scheduler is SchedulerKind.SLURM
                    and not self.capabilities.slurm
                ) or (plan.accelerator_count > 1 and not self.capabilities.multi_gpu):
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU recovery transport lacks frozen capabilities"
                    )
                expected_marker = {
                    "schema_version": _SCHEDULED_GPU_RECOVERY_SCHEMA,
                    "snapshot_sha256": digest,
                    "job_id": job_id,
                    "provider_job_id": value["provider_job_id"],
                    "state": state.value,
                    "attempt": value["attempt"],
                    "prior_snapshot_sha256": previous_sha,
                    "prior_snapshot_event_id": previous_event,
                    "pending_action_key": value["pending_action_key"],
                    "causal_consumption_action_key": value[
                        "causal_consumption_action_key"
                    ],
                    "causal_consumption_event_id": value[
                        "causal_consumption_event_id"
                    ],
                    "causal_consumption_event_hash": value[
                        "causal_consumption_event_hash"
                    ],
                }
                expected_parents = tuple(
                    dict.fromkeys(
                        (
                            value["authority_artifact_sha256"],
                            value["submission_authorization_artifact_sha256"],
                            *((previous_sha,) if previous_sha is not None else ()),
                        )
                    )
                )
                if (
                    dict(marker) != expected_marker
                    or record.sha256 != digest
                    or record.logical_type
                    != _SCHEDULED_GPU_RECOVERY_LOGICAL_TYPE
                    or record.schema_version != "1.0"
                    or record.mime_type != "application/json"
                    or record.size != len(snapshot_source)
                    or record.origin
                    != "source-owned scheduled GPU process recovery snapshot"
                    or record.creator_role is not Role.EXPERIMENT_RUNNER
                    or record.creation_command != _SCHEDULED_GPU_RECOVERY_COMMAND
                    or record.parent_artifacts != expected_parents
                    or record.validation_result != "PASS"
                    or not record.frozen
                    or event.run_id != value["authority_run_id"]
                    or event.actor_role is not Role.EXPERIMENT_RUNNER
                    or event.state_before != event.requested_state_after
                    or event.artifact_hashes != (digest, *expected_parents)
                    or event.code_version != f"sha256:{cloud.code_sha256}"
                    or event.configuration_hash != cloud.configuration_sha256
                    or event.dataset_identifiers != (cloud.data_sha256,)
                    or event.random_seeds != cloud.seeds
                    or event.evaluator_outputs
                    or event.reason
                    != "durably admitted scheduled GPU recovery snapshot"
                    or event.event_type != "CHECKPOINT"
                    or event.supersedes_event_id is not None
                    or thaw_json(event.metadata)
                    != {"scheduled_gpu_recovery_snapshot": expected_marker}
                ):
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU recovery source contract is invalid"
                    )
                for name in (
                    "pending_checkpoint_sha256", "requeued_checkpoint_sha256",
                    "collected_manifest_sha256", "collected_bundle_sha256",
                ):
                    if value.get(name) is not None:
                        validate_sha256(value[name], f"scheduled GPU {name}")
                if not isinstance(value.get("collected_artifact_sha256s"), list):
                    raise ScheduledGPURecoveryBlocked("scheduled GPU collected artifact lineage is malformed")
                for artifact_digest in value["collected_artifact_sha256s"]:
                    validate_sha256(
                        artifact_digest,
                        "scheduled GPU collected artifact SHA-256",
                    )
                if (
                    not isinstance(value.get("network_used"), bool)
                    or isinstance(value.get("attempt"), bool)
                    or not isinstance(value.get("attempt"), int)
                    or not 1 <= value["attempt"] <= 10_000
                    or (
                        value.get("queue_position") is not None
                        and (
                            isinstance(value.get("queue_position"), bool)
                            or not isinstance(value.get("queue_position"), int)
                            or not 0 <= value["queue_position"] <= 10_000_000
                        )
                    )
                ):
                    raise ScheduledGPURecoveryBlocked("scheduled GPU recovery state is malformed")
                causal_event_id = value.get("causal_consumption_event_id")
                causal_event_hash = value.get("causal_consumption_event_hash")
                causal_action_key = value.get("causal_consumption_action_key")
                if not all(isinstance(item, str) for item in (causal_event_id, causal_event_hash, causal_action_key)):
                    raise ScheduledGPURecoveryBlocked("scheduled GPU causal consumption is malformed")
                causal_matches = [
                    (index, candidate)
                    for index, candidate in enumerate(events)
                    if candidate.event_id == causal_event_id
                ]
                if (
                    len(causal_matches) != 1
                    or causal_matches[0][1].event_hash != causal_event_hash
                    or causal_matches[0][0] >= events.index(event)
                    or any(
                        candidate.event_type == "CORRECTION"
                        and candidate.supersedes_event_id == causal_event_id
                        for candidate in events
                    )
                ):
                    raise ScheduledGPURecoveryBlocked("scheduled GPU causal consumption is not live")
                causal_event = causal_matches[0][1]
                causal_value = thaw_json(causal_event.metadata).get(
                    "compute_escalation_submission_consumption"
                )
                if (
                    not isinstance(causal_value, Mapping)
                    or causal_value.get("action_idempotency_key") != causal_action_key
                    or causal_value.get("authority_artifact_sha256")
                    != value.get("authority_artifact_sha256")
                    or causal_value.get("request_sha256") != value.get("request_sha256")
                ):
                    raise ScheduledGPURecoveryBlocked("scheduled GPU causal consumption differs from snapshot")
                if history:
                    tail = history[-1]
                    if (
                        value.get("requeued_from_attempt") != tail.source_attempt
                        or value.get("requeued_checkpoint_sha256") != tail.checkpoint_sha256
                        or value["attempt"] < tail.target_attempt
                    ):
                        raise ScheduledGPURecoveryBlocked("scheduled GPU requeue lineage is inconsistent")
                elif (
                    value.get("requeued_from_attempt") is not None
                    or value.get("requeued_checkpoint_sha256") is not None
                ):
                    raise ScheduledGPURecoveryBlocked("scheduled GPU requeue lineage is missing")
                if (
                    value.get("pending_checkpoint_sha256") is not None
                    and state is not RunState.PREEMPTED
                ):
                    raise ScheduledGPURecoveryBlocked("scheduled GPU pending checkpoint state is invalid")
                if state in {RunState.SUCCEEDED, RunState.FAILED, RunState.CANCELLED, RunState.INVALID_OUTPUT} and value.get("pending_checkpoint_sha256") is not None:
                    raise ScheduledGPURecoveryBlocked("terminal scheduled GPU snapshot attempts to reopen")
                candidate_job = _ScheduledGPUJob(
                    local_spec=local, cloud_spec=cloud, decision=decision, plan=plan,
                    idempotency_key=value["idempotency_key"], job_id=job_id,
                    provider_job_id=value["provider_job_id"], state=state,
                    attempt=value["attempt"], network_used=value["network_used"],
                    authority_artifact_sha256=value["authority_artifact_sha256"],
                    authority_run_id=value["authority_run_id"], authority_id=value["authority_id"],
                    authority_key_sha256=value["authority_key_sha256"],
                    submission_authorization_artifact_sha256=value["submission_authorization_artifact_sha256"],
                    gate_authorization_sha256=value["gate_authorization_sha256"],
                    request_sha256=value["request_sha256"],
                    requeued_from_attempt=value.get("requeued_from_attempt"),
                    requeue_history=history, queue_position=value.get("queue_position"),
                    snapshot_sha256=digest, snapshot_event_id=event.event_id,
                    pending_checkpoint_sha256=value.get("pending_checkpoint_sha256"),
                    requeued_checkpoint_sha256=value.get("requeued_checkpoint_sha256"),
                    pending_action_key=value.get("pending_action_key"),
                    causal_consumption_action_key=causal_action_key,
                    causal_consumption_event_id=causal_event_id,
                    causal_consumption_event_hash=causal_event_hash,
                    collected_manifest_sha256=value.get("collected_manifest_sha256"),
                    collected_artifact_sha256s=tuple(value.get("collected_artifact_sha256s", ())),
                    collected_bundle_sha256=value.get("collected_bundle_sha256"),
                )
                # Reopen the source owners before accepting any durable state.
                authority, gate_sha256, request = (
                    self._require_job_execution_authority(candidate_job)
                )
                if history:
                    tail = history[-1]
                    expected_action_type = "REQUEUE"
                    expected_provider_job_id: str | None = candidate_job.provider_job_id
                    expected_checkpoint_sha256: str | None = tail.checkpoint_sha256
                    expected_preemption_sha256: str | None = causal_value.get(
                        "preemption_snapshot_sha256"
                    )
                    expected_source_attempt = tail.source_attempt
                    expected_target_attempt = tail.target_attempt
                    expected_action_key = tail.action_idempotency_key
                else:
                    expected_action_type = "SUBMIT"
                    expected_provider_job_id = None
                    expected_checkpoint_sha256 = None
                    expected_preemption_sha256 = None
                    expected_source_attempt = 0
                    expected_target_attempt = 1
                    expected_action_key = f"submit-{candidate_job.request_sha256[:24]}"
                expected_consumption = self._attempt_consumption_binding(
                    authority=authority,
                    authority_artifact_sha256=(
                        candidate_job.authority_artifact_sha256
                    ),
                    authority_run_id=candidate_job.authority_run_id,
                    submission_authorization_artifact_sha256=(
                        candidate_job.submission_authorization_artifact_sha256
                    ),
                    gate_authorization_sha256=gate_sha256,
                    request=request,
                    local_spec=candidate_job.local_spec,
                    cloud_spec=candidate_job.cloud_spec,
                    decision=candidate_job.decision,
                    action_type=expected_action_type,
                    provider_job_id=expected_provider_job_id,
                    checkpoint_sha256=expected_checkpoint_sha256,
                    preemption_snapshot_sha256=expected_preemption_sha256,
                    source_attempt=expected_source_attempt,
                    target_attempt=expected_target_attempt,
                    action_idempotency_key=expected_action_key,
                )
                expected_consumption_metadata = {
                    "compute_escalation_submission_consumption": (
                        expected_consumption
                    )
                }
                if (
                    dict(causal_value) != expected_consumption
                    or causal_event.run_id != candidate_job.authority_run_id
                    or causal_event.actor_role is not Role.EXPERIMENT_RUNNER
                    or causal_event.state_before
                    != causal_event.requested_state_after
                    or causal_event.artifact_hashes
                    != (
                        candidate_job.authority_artifact_sha256,
                        candidate_job.submission_authorization_artifact_sha256,
                        *authority.input_artifact_hashes,
                    )
                    or causal_event.code_version
                    != f"sha256:{candidate_job.cloud_spec.code_sha256}"
                    or causal_event.configuration_hash
                    != candidate_job.cloud_spec.configuration_sha256
                    or causal_event.dataset_identifiers
                    != (candidate_job.cloud_spec.data_sha256,)
                    or causal_event.random_seeds != candidate_job.cloud_spec.seeds
                    or causal_event.evaluator_outputs
                    or causal_event.reason
                    != (
                        "consumed one exact compute-escalation attempt authority "
                        f"immediately before scheduled GPU {expected_action_type.lower()}"
                    )
                    or causal_event.event_type != "CHECKPOINT"
                    or causal_event.supersedes_event_id is not None
                    or thaw_json(causal_event.metadata)
                    != expected_consumption_metadata
                ):
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU causal consumption contract is invalid"
                    )
                self._require_recovery_successor(
                    latest,
                    candidate_job,
                    causal_value,
                )
                latest = candidate_job
                previous_sha, previous_event = digest, event.event_id
            assert latest is not None
            resolved_consumption_ids = {
                marker.get("causal_consumption_event_id") for _, marker in chain
            }
            relevant_consumptions: list[tuple[LedgerEvent, Mapping[str, Any]]] = []
            for candidate in events:
                consumption = thaw_json(candidate.metadata).get(
                    "compute_escalation_submission_consumption"
                )
                if (
                    isinstance(consumption, Mapping)
                    and consumption.get("authority_artifact_sha256")
                    == latest.authority_artifact_sha256
                    and consumption.get("request_sha256") == latest.request_sha256
                ):
                    relevant_consumptions.append((candidate, consumption))
            relevant_ids = {item.event_id for item, _ in relevant_consumptions}
            if any(
                candidate.event_type == "CORRECTION"
                and candidate.supersedes_event_id in relevant_ids
                for candidate in events
            ):
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU attempt consumption was corrected"
                )
            unresolved = [
                (candidate, consumption)
                for candidate, consumption in relevant_consumptions
                if candidate.event_id not in resolved_consumption_ids
            ]
            if len(unresolved) > 1:
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU job has ambiguous unresolved actions"
                )
            if unresolved:
                unresolved_key = unresolved[0][1].get("action_idempotency_key")
                if (
                    not isinstance(unresolved_key, str)
                    or latest.pending_action_key is not None
                ):
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU unresolved action differs from durable state"
                    )
                latest.pending_action_key = unresolved_key
            elif (
                latest.pending_action_key is not None
                and not latest.pending_action_key.startswith("cancel-")
            ):
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU durable pending action has no live intent"
                )
            if latest.provider_job_id in seen_provider_ids:
                raise ScheduledGPURecoveryBlocked("scheduled GPU provider identity collision")
            if latest.idempotency_key in seen_idempotency_keys:
                raise ScheduledGPURecoveryBlocked("scheduled GPU idempotency identity collision")
            if latest.cloud_spec.sha256 in seen_cloud_specs:
                raise ScheduledGPURecoveryBlocked("scheduled GPU spec identity collision")
            seen_provider_ids.add(latest.provider_job_id)
            seen_idempotency_keys.add(latest.idempotency_key)
            seen_cloud_specs.add(latest.cloud_spec.sha256)
            restored.append(latest)
        # Replay invokes existing source owners, which take bounded locks of
        # their own.  Reacquire the registry->ledger co-lock and require the
        # exact initial snapshots before publishing any hydrated state.
        registry_guard = self._registry._open_mutation_lock()
        try:
            ledger_guard = self._ledger._open_lock()
            try:
                current_registry = self._registry._verify_all_locked(
                    registry_guard,
                    raise_on_error=True,
                )
                current_ledger = self._ledger._validate_bytes(
                    self._ledger._read_raw_locked(ledger_guard)
                )
                if (
                    current_registry != registry_snapshot
                    or current_ledger != ledger_snapshot
                ):
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU recovery sources changed during replay"
                    )
                for job in restored:
                    self._jobs[job.job_id] = job
                    self._idempotency[job.idempotency_key] = (
                        job.cloud_spec.sha256,
                        job.plan.sha256,
                        job.job_id,
                    )
                    self._spec_jobs[job.cloud_spec.sha256] = job.job_id
                    self._provider_jobs[job.provider_job_id] = job.job_id
            finally:
                self._ledger._unlock(ledger_guard)
        finally:
            self._registry._unlock_mutation(registry_guard)

    def submit(self, spec: FrozenRunSpec, *, idempotency_key: str) -> SubmissionReceipt:
        raise ExperimentError("scheduled GPU submission requires submit_planned")

    def submit_planned(
        self,
        local_spec: FrozenRunSpec,
        cloud_spec: FrozenRunSpec,
        decision: EscalationDecision,
        *,
        idempotency_key: str,
        authority_artifact_sha256: str | None = None,
        authority_run_id: str | None = None,
        submission_authorization_artifact_sha256: str | None = None,
        autonomous_decision: Any = None,
    ) -> SubmissionReceipt:
        if (
            self._registry is None
            or self._ledger is None
            or authority_artifact_sha256 is None
            or authority_run_id is None
        ):
            raise ExperimentError(
                "scheduled GPU submission requires v2 compute authority"
            )
        if submission_authorization_artifact_sha256 is None:
            if autonomous_decision is None:
                raise ExperimentError(
                    "scheduled GPU submission requires a plan-bound autonomous decision"
                )
        elif autonomous_decision is not None:
            raise ExperimentError(
                "scheduled GPU submission accepts either a decision or preissued authorization"
            )
        if autonomous_decision is not None:
            from .gates import AutonomousDecisionRecord

            if type(autonomous_decision) is not AutonomousDecisionRecord:
                raise ExperimentError(
                    "scheduled GPU submission decision must be an exact typed value"
                )
        validate_identifier(idempotency_key, "scheduled GPU idempotency key")
        authority = require_compute_escalation_plan_authority(
            self._registry,
            self._ledger,
            authority_artifact_sha256=authority_artifact_sha256,
            expected_run_id=authority_run_id,
            expected_decision_id=decision.decision_id,
        )
        _, plan_value = _load_compute_escalation_input(
            self._registry,
            authority.submission_plan_artifact_sha256,
            run_id=authority_run_id,
            logical_type=COMPUTE_ESCALATION_PLAN_LOGICAL_TYPE,
            creator_role=Role.PROTOCOL_DESIGNER,
        )
        plan = _parse_submission_plan(plan_value)
        if (
            authority.run_id != authority_run_id
            or authority.local_spec_sha256 != local_spec.sha256
            or authority.cloud_spec_sha256 != cloud_spec.sha256
            or authority.project_definition_sha256
            != cloud_spec.project_definition_sha256
            or authority.decision_sha256 != decision.sha256
            or authority.submission_plan_sha256 != plan.sha256
        ):
            raise ExperimentError(
                "scheduled GPU authority names another run, plan, or budget"
            )
        if plan.scheduler not in {SchedulerKind.SCHEDULED, SchedulerKind.SLURM}:
            raise ExperimentError("scheduled GPU backend requires scheduled or SLURM execution")
        if plan.scheduler is SchedulerKind.SLURM and not self.capabilities.slurm:
            raise ExperimentError("transport does not support the requested SLURM scheduler")
        if plan.accelerator_count > 1 and not self.capabilities.multi_gpu:
            raise ExperimentError("transport does not support the requested multi-GPU job")
        request = ScheduledGPURequest(cloud_spec, plan, idempotency_key)
        request_sha256 = hashlib.sha256(
            canonical_json_bytes(request.to_dict())
        ).hexdigest()
        submission_action_key = f"submit-{request_sha256[:24]}"
        with self._lock:
            previous = self._idempotency.get(idempotency_key)
            if previous is not None:
                prior_spec_sha256, prior_plan_sha256, job_id = previous
                if (prior_spec_sha256, prior_plan_sha256) != (cloud_spec.sha256, plan.sha256):
                    raise SubmissionConflictError(
                        "scheduled GPU idempotency key names different work"
                    )
                existing = self._job(job_id)
                if (
                    existing.authority_artifact_sha256
                    != authority_artifact_sha256
                    or existing.authority_run_id != authority_run_id
                    or (
                        submission_authorization_artifact_sha256 is not None
                        and existing.submission_authorization_artifact_sha256
                        != submission_authorization_artifact_sha256
                    )
                ):
                    raise SubmissionConflictError(
                        "scheduled GPU idempotency replay changed its authority"
                    )
                gate_sha256 = _require_compute_escalation_submission_authorization(
                    self._registry,
                    self._ledger,
                    submission_authorization_artifact_sha256=(
                        existing.submission_authorization_artifact_sha256
                    ),
                    authority_artifact_sha256=authority_artifact_sha256,
                    authority_run_id=authority_run_id,
                    authority=authority,
                    local_spec=local_spec,
                    cloud_spec=cloud_spec,
                    decision=decision,
                    plan=plan,
                    request=request,
                    expected_autonomous_decision=autonomous_decision,
                )
                if gate_sha256 != existing.gate_authorization_sha256:
                    raise ExperimentError(
                        "scheduled GPU gate authorization differs from its frozen replay"
                    )
                self._persist_recovery_snapshot(existing)
                return self._receipt(existing)
            existing_job_id = self._spec_jobs.get(cloud_spec.sha256)
            if existing_job_id is not None:
                raise SubmissionConflictError(
                    "scheduled GPU spec was already submitted under another request"
                )
            recovered_authorization_sha256 = (
                self._recover_consumed_submission_authorization(
                    authority_artifact_sha256=authority_artifact_sha256,
                    request=request,
                    action_idempotency_key=submission_action_key,
                )
            )
            # A consumption checkpoint is deliberately before transport.  If
            # it exists but no response snapshot was admitted, another submit
            # could purchase duplicate work; idempotency is not a transport
            # exactly-once contract.
            if recovered_authorization_sha256 is not None:
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU submit has an ambiguous consumed transport window"
                )
            if (
                recovered_authorization_sha256 is not None
                and submission_authorization_artifact_sha256 is not None
                and recovered_authorization_sha256
                != submission_authorization_artifact_sha256
            ):
                raise SubmissionConflictError(
                    "scheduled GPU submit recovery changed its authorization"
                )
            if submission_authorization_artifact_sha256 is None:
                submission_authorization_artifact_sha256 = (
                    recovered_authorization_sha256
                    or register_compute_escalation_submission_authorization(
                        self._registry,
                        self._ledger,
                        authority_artifact_sha256=authority_artifact_sha256,
                        authority_run_id=authority_run_id,
                        local_spec=local_spec,
                        cloud_spec=cloud_spec,
                        decision=decision,
                        idempotency_key=idempotency_key,
                        autonomous_decision=autonomous_decision,
                    ).sha256
                )
            gate_sha256 = _require_compute_escalation_submission_authorization(
                self._registry,
                self._ledger,
                submission_authorization_artifact_sha256=(
                    submission_authorization_artifact_sha256
                ),
                authority_artifact_sha256=authority_artifact_sha256,
                authority_run_id=authority_run_id,
                authority=authority,
                local_spec=local_spec,
                cloud_spec=cloud_spec,
                decision=decision,
                plan=plan,
                request=request,
                expected_autonomous_decision=autonomous_decision,
            )
            recovery_job_id = f"scheduled-gpu-{plan.sha256[:20]}"
            self._preflight_recovery_capacity(
                job_id=recovery_job_id,
                required_snapshots=1,
            )
            consumption_event = self._consume_attempt_authority(
                authority=authority,
                authority_artifact_sha256=authority_artifact_sha256,
                authority_run_id=authority_run_id,
                submission_authorization_artifact_sha256=(
                    submission_authorization_artifact_sha256
                ),
                gate_authorization_sha256=gate_sha256,
                request=request,
                local_spec=local_spec,
                cloud_spec=cloud_spec,
                decision=decision,
                action_type="SUBMIT",
                provider_job_id=None,
                checkpoint_sha256=None,
                preemption_snapshot_sha256=None,
                preemption_snapshot_event_id=None,
                recovery_job_id=recovery_job_id,
                source_attempt=0,
                target_attempt=1,
                action_idempotency_key=submission_action_key,
                require_fresh_authority_head=True,
                allow_exact_recovery=False,
            )
            remote_status = self._transport.submit(request)
            if not isinstance(remote_status, ScheduledGPUStatus):
                raise ExperimentError("scheduler transport returned an invalid submission status")
            if remote_status.state is RunState.INVALID_OUTPUT:
                raise ExperimentError("scheduler cannot submit work as INVALID_OUTPUT")
            if remote_status.provider_job_id in self._provider_jobs:
                raise SubmissionConflictError("provider job identity was reused")
            if remote_status.attempt != 1:
                raise ExperimentIntegrityError(
                    "scheduler submission must begin at attempt one"
                )
            network_used_snapshot = self._transport_network_snapshot()
            job_id = f"scheduled-gpu-{plan.sha256[:20]}"
            job = _ScheduledGPUJob(
                local_spec=local_spec,
                cloud_spec=cloud_spec,
                decision=decision,
                plan=plan,
                idempotency_key=idempotency_key,
                job_id=job_id,
                provider_job_id=remote_status.provider_job_id,
                state=RunState.SUBMITTED,
                attempt=remote_status.attempt,
                network_used=network_used_snapshot,
                authority_artifact_sha256=authority_artifact_sha256,
                authority_run_id=authority_run_id,
                authority_id=authority.authority_id,
                authority_key_sha256=authority.authority_key_sha256,
                submission_authorization_artifact_sha256=(
                    submission_authorization_artifact_sha256
                ),
                gate_authorization_sha256=gate_sha256,
                request_sha256=request_sha256,
                pending_action_key=None,
                causal_consumption_action_key=submission_action_key,
                causal_consumption_event_id=consumption_event.event_id,
                causal_consumption_event_hash=consumption_event.event_hash,
            )
            self._apply_status(job, remote_status)
            # Publish neither the job nor any of its uniqueness indexes until
            # the exact provider response has a durable registry+ledger head.
            self._persist_recovery_snapshot(job)
            self._jobs[job_id] = job
            self._idempotency[idempotency_key] = (
                cloud_spec.sha256,
                plan.sha256,
                job_id,
            )
            self._spec_jobs[cloud_spec.sha256] = job_id
            self._provider_jobs[remote_status.provider_job_id] = job_id
            return self._receipt(job)

    def reconcile(self, job_id: str) -> JobStatus:
        with self._lock:
            job = self._job(job_id)
            terminal = job.state in {
                RunState.SUCCEEDED, RunState.FAILED, RunState.CANCELLED,
                RunState.INVALID_OUTPUT,
            }
            provider_job_id = job.provider_job_id
        if not terminal:
            remote_status = self._transport.status(provider_job_id)
            with self._lock:
                job = self._job(job_id)
                if job.provider_job_id != provider_job_id:
                    raise ScheduledGPURecoveryBlocked(
                        "scheduled GPU job changed during status reconciliation"
                    )
                staged = self._stage_job(job)
                self._record_transport_network_use(staged)
                self._apply_status(staged, remote_status)
                try:
                    self._persist_recovery_snapshot(staged)
                except Exception:
                    # The durable predecessor remains authoritative, but this
                    # live instance has observed an unpublishable response and
                    # may not later expose or act on it.
                    job.durability_blocked = True
                    raise
                self._jobs[job_id] = staged
        with self._lock:
            job = self._job(job_id)
            self._persist_recovery_snapshot(job)
            return self._status(job)

    def cancel(self, job_id: str) -> JobStatus:
        # Intent is durable before an externally visible cancellation.  A
        # missing response is therefore reconciled by status, never retried.
        with self._lock:
            job = self._job(job_id)
            if job.pending_action_key is not None:
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU job already has an unresolved action"
                )
            if job.state in {
                RunState.SUCCEEDED,
                RunState.FAILED,
                RunState.CANCELLED,
                RunState.INVALID_OUTPUT,
            }:
                self._persist_recovery_snapshot(job)
                return self._status(job)
            action_key = f"cancel-{hashlib.sha256(job.job_id.encode('utf-8')).hexdigest()[:24]}"
            self._preflight_recovery_capacity(
                job_id=job.job_id,
                required_snapshots=2,
            )
            intent = self._stage_job(job)
            intent.pending_action_key = action_key
            self._persist_recovery_snapshot(
                intent,
                required_successor_snapshots=1,
            )
            self._jobs[job_id] = intent
            provider_job_id = intent.provider_job_id
        remote_status = self._transport.cancel(provider_job_id, idempotency_key=action_key)
        with self._lock:
            job = self._job(job_id)
            if job.provider_job_id != provider_job_id or job.pending_action_key != action_key:
                raise ScheduledGPURecoveryBlocked("scheduled GPU cancel changed during transport")
            staged = self._stage_job(job)
            self._record_transport_network_use(staged)
            self._apply_status(staged, remote_status)
            staged.pending_action_key = None
            try:
                self._persist_recovery_snapshot(staged)
            except Exception:
                job.durability_blocked = True
                raise
            self._jobs[job_id] = staged
            return self._status(staged)

    def preemption_checkpoint(self, job_id: str) -> str | None:
        with self._lock:
            return self._job(job_id).checkpoint_token

    def requeue_from_checkpoint(
        self,
        job_id: str,
        *,
        checkpoint_token: str,
    ) -> JobStatus:
        checkpoint_token = _opaque_reference(
            checkpoint_token,
            "scheduled GPU checkpoint token",
            4_096,
        )
        with self._lock:
            needs_restore_status = (
                self._job(job_id).state is RunState.PREEMPTED
                and self._job(job_id).checkpoint_token is None
                and self._job(job_id).pending_checkpoint_sha256 is not None
            )
        if needs_restore_status:
            # A restored token is not trusted from disk.  Retain it only from
            # a read-only status response whose digest matches the frozen one.
            try:
                self.reconcile(job_id)
            except ExperimentIntegrityError as exc:
                raise ScheduledGPURecoveryBlocked(
                    "restored scheduled GPU checkpoint cannot be reconciled"
                ) from exc
        with self._lock:
            job = self._job(job_id)
            if self._provider_jobs.get(job.provider_job_id) != job.job_id:
                raise ExperimentIntegrityError(
                    "scheduled GPU provider job identity was substituted"
                )
            if job.pending_action_key is not None:
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU job already has an unresolved action"
                )
            authority, gate_sha256, request = (
                self._require_job_execution_authority(job)
            )
            if job.state is not RunState.PREEMPTED or job.checkpoint_token is None:
                if (
                    job.requeued_checkpoint_sha256
                    == hashlib.sha256(checkpoint_token.encode("utf-8")).hexdigest()
                    and job.requeued_from_attempt is not None
                    and job.attempt == job.requeued_from_attempt + 1
                ):
                    self._persist_recovery_snapshot(job)
                    return self._status(job)
                raise ExperimentError("only a checkpointed GPU job may be requeued")
            if checkpoint_token != job.checkpoint_token:
                raise ExperimentIntegrityError("GPU checkpoint changed before requeue")
            source_attempt = job.attempt
            checkpoint_sha256 = hashlib.sha256(checkpoint_token.encode("utf-8")).hexdigest()
            action_key = (
                f"requeue-{checkpoint_sha256[:16]}-attempt-{job.attempt + 1}-"
                f"{hashlib.sha256(job.provider_job_id.encode('utf-8')).hexdigest()[:8]}"
            )
            if self._consumption_action_exists(action_key):
                raise ScheduledGPURecoveryBlocked(
                    "scheduled GPU requeue has an ambiguous consumed transport window"
                )
            self._preflight_recovery_capacity(
                job_id=job.job_id,
                required_snapshots=1,
            )
            consumption_event = self._consume_attempt_authority(
                authority=authority,
                authority_artifact_sha256=job.authority_artifact_sha256,
                authority_run_id=job.authority_run_id,
                submission_authorization_artifact_sha256=(
                    job.submission_authorization_artifact_sha256
                ),
                gate_authorization_sha256=gate_sha256,
                request=request,
                local_spec=job.local_spec,
                cloud_spec=job.cloud_spec,
                decision=job.decision,
                action_type="REQUEUE",
                provider_job_id=job.provider_job_id,
                checkpoint_sha256=checkpoint_sha256,
                preemption_snapshot_sha256=job.snapshot_sha256,
                preemption_snapshot_event_id=job.snapshot_event_id,
                recovery_job_id=job.job_id,
                source_attempt=source_attempt,
                target_attempt=source_attempt + 1,
                action_idempotency_key=action_key,
                require_fresh_authority_head=False,
                allow_exact_recovery=False,
            )
            # The consumption is the durable intent.  Retain the prior
            # published job as unresolved until a response snapshot commits.
            job.pending_action_key = action_key
            provider_job_id = job.provider_job_id
        remote_status = self._transport.requeue(
            provider_job_id,
            checkpoint_token=checkpoint_token,
            idempotency_key=action_key,
        )
        with self._lock:
            job = self._job(job_id)
            if job.provider_job_id != provider_job_id or job.pending_action_key != action_key:
                raise ScheduledGPURecoveryBlocked("scheduled GPU requeue changed during transport")
            staged = self._stage_job(job)
            self._record_transport_network_use(staged)
            if not isinstance(remote_status, ScheduledGPUStatus):
                raise ExperimentError("scheduler transport returned an invalid requeue status")
            if remote_status.state not in {RunState.QUEUED, RunState.RUNNING}:
                raise ExperimentIntegrityError(
                    "scheduler requeue did not create queued or running work"
                )
            self._apply_status(
                staged,
                remote_status,
                allow_attempt_increment=True,
            )
            staged.requeued_checkpoint_sha256 = checkpoint_sha256
            staged.causal_consumption_event_id = consumption_event.event_id
            staged.causal_consumption_event_hash = consumption_event.event_hash
            staged.causal_consumption_action_key = action_key
            staged.requeued_from_attempt = source_attempt
            staged.requeue_history = (
                *staged.requeue_history,
                GPURequeueLineage(
                    source_attempt=source_attempt,
                    target_attempt=staged.attempt,
                    checkpoint_sha256=checkpoint_sha256,
                    action_idempotency_key=action_key,
                ),
            )
            staged.checkpoint_token = None
            staged.pending_checkpoint_sha256 = None
            staged.pending_action_key = None
            try:
                self._persist_recovery_snapshot(staged)
            except Exception:
                job.durability_blocked = True
                raise
            self._jobs[job_id] = staged
            return self._status(staged)

    def requeue_lineage(self, job_id: str) -> tuple[GPURequeueLineage, ...]:
        with self._lock:
            job = self._job(job_id)
            self._persist_recovery_snapshot(job)
            return job.requeue_history

    def queue_position(self, job_id: str) -> int | None:
        return self.reconcile(job_id).queue_position

    def _capture_bundle(self, job: _ScheduledGPUJob) -> ScheduledGPUArtifactBundle:
        bundle = self._transport.collect(job.provider_job_id)
        self._record_transport_network_use(job)
        if not isinstance(bundle, ScheduledGPUArtifactBundle):
            raise ExperimentIntegrityError(
                "scheduler transport returned an invalid artifact bundle"
            )
        expected_resumed_checkpoint_sha256 = job.requeued_checkpoint_sha256
        if bundle.provider_job_id != job.provider_job_id:
            raise ExperimentIntegrityError(
                "scheduler artifact bundle changed provider job identity"
            )
        if bundle.spec_sha256 != job.cloud_spec.sha256:
            raise ExperimentIntegrityError("scheduler artifact bundle changed run spec")
        if bundle.submission_plan_sha256 != job.plan.sha256:
            raise ExperimentIntegrityError("scheduler artifact bundle changed submission plan")
        if bundle.attempt != job.attempt:
            raise ExperimentIntegrityError("scheduler artifact bundle changed current attempt")
        if bundle.resumed_checkpoint_sha256 != expected_resumed_checkpoint_sha256:
            raise ExperimentIntegrityError(
                "scheduler artifact bundle changed resumed checkpoint identity"
            )
        if bundle.requeue_history != job.requeue_history:
            raise ExperimentIntegrityError(
                "scheduler artifact bundle changed ordered requeue lineage"
            )
        _validate_manifest_bindings(job.cloud_spec, bundle.manifest)
        manifest_sha256 = hashlib.sha256(bundle.manifest_bytes).hexdigest()
        artifact_sha256s = tuple(item.descriptor.sha256 for item in bundle.artifacts)
        bundle_sha256 = hashlib.sha256(
            canonical_json_bytes(
                {
                    "manifest_sha256": manifest_sha256,
                    "artifact_sha256s": list(artifact_sha256s),
                    "attempt": bundle.attempt,
                    "resumed_checkpoint_sha256": bundle.resumed_checkpoint_sha256,
                    "requeue_history": [item.to_dict() for item in bundle.requeue_history],
                }
            )
        ).hexdigest()
        if (
            job.collected_bundle_sha256 is not None
            and (
                job.collected_manifest_sha256 != manifest_sha256
                or job.collected_artifact_sha256s != artifact_sha256s
                or job.collected_bundle_sha256 != bundle_sha256
            )
        ):
            raise ExperimentIntegrityError(
                "scheduler artifact refetch differs from the durable collected identity"
            )
        job.bundle = bundle
        job.collected_manifest_sha256 = manifest_sha256
        job.collected_artifact_sha256s = artifact_sha256s
        job.collected_bundle_sha256 = bundle_sha256
        return bundle

    def collect(self, job_id: str) -> CollectedRun:
        with self._lock:
            job = self._job(job_id)
            if job.state not in {
                RunState.SUCCEEDED,
                RunState.FAILED,
                RunState.CANCELLED,
                RunState.INVALID_OUTPUT,
            }:
                remote_status = self._transport.status(job.provider_job_id)
                staged = self._stage_job(job)
                self._record_transport_network_use(staged)
                self._apply_status(staged, remote_status)
                try:
                    self._persist_recovery_snapshot(staged)
                except Exception:
                    job.durability_blocked = True
                    raise
                self._jobs[job_id] = staged
                job = staged
            if job.state is not RunState.SUCCEEDED:
                raise ExperimentIntegrityError("scheduled GPU job is not successfully collectable")
            if job.bundle is None:
                staged = self._stage_job(job)
                try:
                    bundle = self._capture_bundle(staged)
                except (ValidationError, ExperimentIntegrityError) as exc:
                    # Persist only a source-owned invalid-output disposition;
                    # the untrusted bundle and provider text remain outside
                    # the recovery boundary.
                    staged.bundle = None
                    staged.state = RunState.INVALID_OUTPUT
                    staged.reason = "RETURNED_ARTIFACT_INVALID_UNATTESTED"
                    try:
                        self._persist_recovery_snapshot(staged)
                    except Exception:
                        job.durability_blocked = True
                        raise
                    self._jobs[job_id] = staged
                    raise ExperimentIntegrityError(
                        "scheduled GPU artifact return is invalid"
                    ) from exc
                try:
                    self._persist_recovery_snapshot(staged)
                except Exception:
                    # A validated response is not observable until its exact
                    # output identity has durable registry+ledger admission.
                    job.durability_blocked = True
                    raise
                self._jobs[job_id] = staged
                job = staged
            else:
                # Even a cached result is live only while its durable head and
                # causal consumption remain current and uncorrected.
                self._persist_recovery_snapshot(job)
                bundle = job.bundle
            assert bundle is not None
            return CollectedRun(
                backend_id=self.backend_id,
                spec=job.cloud_spec,
                manifest=bundle.manifest,
                manifest_sha256=hashlib.sha256(bundle.manifest_bytes).hexdigest(),
                manifest_bytes=bundle.manifest_bytes,
                network_used=job.network_used,
                scientific_evidence=False,
                validation_status=ValidationStatus.UNTESTED,
                execution_plan_sha256=job.plan.sha256,
                returned_artifact_sha256s=tuple(
                    item.descriptor.sha256 for item in bundle.artifacts
                ),
                network_isolation_attested=False,
            )

    def staged_artifacts(self, job_id: str) -> tuple[StagedArtifact, ...]:
        # ``collect`` may atomically replace the live job after admitting its
        # bundle, so reacquire rather than retaining the pre-admission object.
        self.collect(job_id)
        with self._lock:
            job = self._job(job_id)
            assert job.bundle is not None
            return job.bundle.artifacts

    def returned_artifacts(self, job_id: str) -> tuple[str, ...]:
        return tuple(item.descriptor.sha256 for item in self.staged_artifacts(job_id))

    def collect_into_registry(
        self,
        job_id: str,
        *,
        creator_role: Role,
        parent_artifacts: Iterable[str] = (),
        registry: ArtifactRegistry | None = None,
    ) -> RegisteredGPUArtifacts:
        target_registry = registry or self._registry
        if not isinstance(target_registry, ArtifactRegistry):
            raise ExperimentError("GPU artifact return requires an ArtifactRegistry")
        if creator_role is not Role.EXPERIMENT_RUNNER:
            raise ExperimentError(
                "GPU artifact return must use the backend-owned experiment-runner role"
            )
        parents = tuple(dict.fromkeys(parent_artifacts))
        for parent_sha256 in parents:
            validate_sha256(parent_sha256, "GPU artifact parent SHA-256")
        collected = self.collect(job_id)
        if (
            hashlib.sha256(collected.manifest_bytes).hexdigest()
            != collected.manifest_sha256
        ):
            raise ExperimentIntegrityError(
                "collected GPU manifest bytes changed before publication"
            )
        try:
            collected_manifest_value = safe_json_loads(
                collected.manifest_bytes,
                max_bytes=MAX_OUTPUT_MANIFEST_BYTES,
            )
        except ValidationError as exc:
            raise ExperimentIntegrityError(
                "collected GPU manifest bytes are malformed before publication"
            ) from exc
        if (
            not isinstance(collected_manifest_value, Mapping)
            or dict(collected_manifest_value) != collected.manifest.to_dict()
        ):
            raise ExperimentIntegrityError(
                "collected GPU manifest bytes changed semantic identity before publication"
            )
        with self._lock:
            job = self._job(job_id)
            assert job.bundle is not None
            bundle = job.bundle
            command = ("scientist-one", "gpu-cloud-artifact-return")
            origin_prefix = f"gpu-cloud:{self.provider_name}:{job.job_id}"
            source_spec_record = target_registry.put_bytes(
                canonical_json_bytes(job.local_spec.to_dict()),
                logical_type="gpu_cloud_source_run_spec",
                origin=f"{origin_prefix}:source-spec",
                creator_role=creator_role,
                creation_command=command,
                parent_artifacts=parents,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            target_spec_record = target_registry.put_bytes(
                canonical_json_bytes(job.cloud_spec.to_dict()),
                logical_type="gpu_cloud_target_run_spec",
                origin=f"{origin_prefix}:target-spec",
                creator_role=creator_role,
                creation_command=command,
                parent_artifacts=parents,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            plan_record = target_registry.put_bytes(
                canonical_json_bytes(job.plan.to_dict()),
                logical_type="gpu_cloud_submission_plan",
                origin=f"{origin_prefix}:submission-plan",
                creator_role=creator_role,
                creation_command=command,
                parent_artifacts=tuple(
                    dict.fromkeys((target_spec_record.sha256, *parents))
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            decision_record = target_registry.put_bytes(
                canonical_json_bytes(job.decision.to_dict()),
                logical_type="gpu_cloud_escalation_decision",
                origin=f"{origin_prefix}:escalation-decision",
                creator_role=creator_role,
                creation_command=command,
                parent_artifacts=tuple(
                    dict.fromkeys(
                        (
                            source_spec_record.sha256,
                            target_spec_record.sha256,
                            plan_record.sha256,
                            *parents,
                        )
                    )
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            manifest_record = target_registry.put_bytes(
                collected.manifest_bytes,
                logical_type="gpu_cloud_output_manifest",
                origin=f"{origin_prefix}:manifest",
                creator_role=creator_role,
                creation_command=command,
                parent_artifacts=tuple(
                    dict.fromkeys(
                        (
                            target_spec_record.sha256,
                            plan_record.sha256,
                            decision_record.sha256,
                            *parents,
                        )
                    )
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            receipt_payload = {
                "schema_version": "SCIENTIST_ONE_GPU_RETURN_RECEIPT_V1",
                "backend_id": self.backend_id,
                "provider_name": self.provider_name,
                "job_id": job.job_id,
                "provider_job_id": bundle.provider_job_id,
                "source_spec_sha256": job.local_spec.sha256,
                "target_spec_sha256": bundle.spec_sha256,
                "submission_plan_sha256": bundle.submission_plan_sha256,
                "escalation_decision_sha256": job.decision.sha256,
                "manifest_sha256": manifest_record.sha256,
                "returned_artifact_sha256s": [
                    item.descriptor.sha256 for item in job.bundle.artifacts
                ],
                "attempt": bundle.attempt,
                "requeued_from_attempt": job.requeued_from_attempt,
                "resumed_from_checkpoint_sha256": bundle.resumed_checkpoint_sha256,
                "pending_checkpoint_sha256": (
                    hashlib.sha256(job.checkpoint_token.encode("utf-8")).hexdigest()
                    if job.checkpoint_token is not None
                    else None
                ),
                "requeue_history": [item.to_dict() for item in bundle.requeue_history],
                "network_used": job.network_used,
                "network_isolation_attested": False,
                "network_use_status": collected.network_use_status.value,
                "external_validation": ValidationStatus.UNTESTED.value,
                "scientific_evidence": False,
                "validation_scope": "BYTE_INTEGRITY_AND_FROZEN_BINDINGS_ONLY",
            }
            receipt_record = target_registry.put_bytes(
                canonical_json_bytes(receipt_payload),
                logical_type="gpu_cloud_return_receipt",
                origin=f"{origin_prefix}:return-receipt",
                creator_role=creator_role,
                creation_command=command,
                parent_artifacts=tuple(
                    dict.fromkeys(
                        (
                            source_spec_record.sha256,
                            target_spec_record.sha256,
                            plan_record.sha256,
                            decision_record.sha256,
                            manifest_record.sha256,
                            *parents,
                        )
                    )
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
            )
            artifact_parents = (receipt_record.sha256, manifest_record.sha256)
            records = tuple(
                target_registry.put_bytes(
                    item.payload,
                    logical_type="gpu_cloud_returned_artifact",
                    origin=(
                        f"gpu-cloud:{self.provider_name}:{job.job_id}:"
                        f"{item.descriptor.sha256[:16]}"
                    ),
                    creator_role=creator_role,
                    creation_command=command,
                    parent_artifacts=artifact_parents,
                    schema_version="1.0",
                    mime_type="application/octet-stream",
                    validation_result="PASS",
                    frozen=True,
                )
                for item in job.bundle.artifacts
            )
        return RegisteredGPUArtifacts(
            collected_run=collected,
            source_spec_record=source_spec_record,
            target_spec_record=target_spec_record,
            submission_plan_record=plan_record,
            escalation_decision_record=decision_record,
            manifest_record=manifest_record,
            return_receipt_record=receipt_record,
            artifact_records=records,
        )


@dataclass(frozen=True, slots=True)
class ScientificBackendAttestationProfile:
    """Opaque selector for a source-owned backend-attestation verifier.

    A profile is only a request to the closed dispatcher.  Constructing this
    value does not prove that a verifier or trust root exists.
    """

    backend_id: str
    attestation_schema: str
    verifier_id: str
    trust_root_id: str

    def __post_init__(self) -> None:
        validate_identifier(self.backend_id, "scientific backend ID")
        for name in ("attestation_schema", "verifier_id", "trust_root_id"):
            object.__setattr__(
                self,
                name,
                _bounded_text(getattr(self, name), name.replace("_", " "), 512),
            )

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (
            self.backend_id,
            self.attestation_schema,
            self.verifier_id,
            self.trust_root_id,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "backend_id": self.backend_id,
            "attestation_schema": self.attestation_schema,
            "verifier_id": self.verifier_id,
            "trust_root_id": self.trust_root_id,
        }

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> "ScientificBackendAttestationProfile":
        expected = {
            "backend_id",
            "attestation_schema",
            "verifier_id",
            "trust_root_id",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ExperimentError(
                "scientific backend attestation profile schema is invalid"
            )
        try:
            return cls(**{name: value[name] for name in expected})
        except (TypeError, ValueError) as exc:
            raise ExperimentError(
                "scientific backend attestation profile is malformed"
            ) from exc


@dataclass(frozen=True, slots=True)
class ScientificExecutionArtifactBinding:
    """Exact registry identity named by an authenticated activity row."""

    artifact_sha256: str
    artifact_record_hash: str

    def __post_init__(self) -> None:
        validate_sha256(self.artifact_sha256, "activity artifact SHA-256")
        validate_sha256(self.artifact_record_hash, "activity artifact record hash")

    def to_dict(self) -> dict[str, str]:
        return {
            "artifact_sha256": self.artifact_sha256,
            "artifact_record_hash": self.artifact_record_hash,
        }

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> "ScientificExecutionArtifactBinding":
        if not isinstance(value, Mapping) or set(value) != {
            "artifact_sha256",
            "artifact_record_hash",
        }:
            raise ExperimentError("scientific activity artifact binding is invalid")
        try:
            return cls(
                artifact_sha256=value["artifact_sha256"],
                artifact_record_hash=value["artifact_record_hash"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ExperimentError(
                "scientific activity artifact binding is malformed"
            ) from exc


@dataclass(frozen=True, slots=True)
class ScientificExecutionActivityRow:
    """One ordered backend-captured action, without a caller-supplied verdict."""

    sequence: int
    kind: ScientificExecutionActivityKind
    seed: int | None
    condition_id: str | None
    ablation_id: str | None
    input_artifact_bindings: tuple[ScientificExecutionArtifactBinding, ...]
    output_artifact_bindings: tuple[ScientificExecutionArtifactBinding, ...]
    dataset_artifact_binding: ScientificExecutionArtifactBinding | None
    split_artifact_binding: ScientificExecutionArtifactBinding | None
    dataset_access_purpose: ScientificDatasetAccessPurpose | None

    def __post_init__(self) -> None:
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 0
        ):
            raise ExperimentError("scientific activity sequence is invalid")
        if not isinstance(self.kind, ScientificExecutionActivityKind):
            try:
                object.__setattr__(
                    self,
                    "kind",
                    ScientificExecutionActivityKind(self.kind),
                )
            except (TypeError, ValueError) as exc:
                raise ExperimentError("scientific activity kind is invalid") from exc
        if self.seed is not None and (
            isinstance(self.seed, bool)
            or not isinstance(self.seed, int)
            or self.seed < 0
        ):
            raise ExperimentError("scientific activity seed is invalid")
        for name in ("condition_id", "ablation_id"):
            value = getattr(self, name)
            if value is not None:
                validate_identifier(value, name.replace("_", " "))
        for name in ("input_artifact_bindings", "output_artifact_bindings"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or len(values) > MAX_ARTIFACT_PARENTS:
                raise ExperimentError(f"scientific activity {name} is invalid")
            if not all(
                isinstance(value, ScientificExecutionArtifactBinding)
                for value in values
            ):
                raise ExperimentError(f"scientific activity {name} is malformed")
            if len({value.artifact_sha256 for value in values}) != len(values):
                raise ExperimentError(f"scientific activity {name} is duplicated")
        dataset_values = (
            self.dataset_artifact_binding,
            self.split_artifact_binding,
            self.dataset_access_purpose,
        )
        if self.kind is ScientificExecutionActivityKind.DATASET_READ:
            if (
                not isinstance(
                    self.dataset_artifact_binding,
                    ScientificExecutionArtifactBinding,
                )
                or not isinstance(
                    self.split_artifact_binding,
                    ScientificExecutionArtifactBinding,
                )
                or not isinstance(
                    self.dataset_access_purpose,
                    ScientificDatasetAccessPurpose,
                )
            ):
                raise ExperimentError(
                    "dataset-read activity lacks its exact dataset, split, or purpose"
                )
        elif any(value is not None for value in dataset_values):
            raise ExperimentError(
                "non-dataset activity cannot carry dataset access authority"
            )

    @property
    def artifact_bindings(self) -> tuple[ScientificExecutionArtifactBinding, ...]:
        result = (*self.input_artifact_bindings, *self.output_artifact_bindings)
        if self.dataset_artifact_binding is not None:
            result += (self.dataset_artifact_binding,)
        if self.split_artifact_binding is not None:
            result += (self.split_artifact_binding,)
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "kind": self.kind.value,
            "seed": self.seed,
            "condition_id": self.condition_id,
            "ablation_id": self.ablation_id,
            "input_artifact_bindings": [
                value.to_dict() for value in self.input_artifact_bindings
            ],
            "output_artifact_bindings": [
                value.to_dict() for value in self.output_artifact_bindings
            ],
            "dataset_artifact_binding": (
                None
                if self.dataset_artifact_binding is None
                else self.dataset_artifact_binding.to_dict()
            ),
            "split_artifact_binding": (
                None
                if self.split_artifact_binding is None
                else self.split_artifact_binding.to_dict()
            ),
            "dataset_access_purpose": (
                None
                if self.dataset_access_purpose is None
                else self.dataset_access_purpose.value
            ),
        }

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> "ScientificExecutionActivityRow":
        expected = {field.name for field in dataclass_fields(cls)}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ExperimentError("scientific execution activity row is invalid")
        try:
            dataset_binding = value["dataset_artifact_binding"]
            split_binding = value["split_artifact_binding"]
            purpose = value["dataset_access_purpose"]
            return cls(
                sequence=value["sequence"],
                kind=ScientificExecutionActivityKind(value["kind"]),
                seed=value["seed"],
                condition_id=value["condition_id"],
                ablation_id=value["ablation_id"],
                input_artifact_bindings=tuple(
                    ScientificExecutionArtifactBinding.from_mapping(item)
                    for item in value["input_artifact_bindings"]
                ),
                output_artifact_bindings=tuple(
                    ScientificExecutionArtifactBinding.from_mapping(item)
                    for item in value["output_artifact_bindings"]
                ),
                dataset_artifact_binding=(
                    None
                    if dataset_binding is None
                    else ScientificExecutionArtifactBinding.from_mapping(
                        dataset_binding
                    )
                ),
                split_artifact_binding=(
                    None
                    if split_binding is None
                    else ScientificExecutionArtifactBinding.from_mapping(split_binding)
                ),
                dataset_access_purpose=(
                    None
                    if purpose is None
                    else ScientificDatasetAccessPurpose(purpose)
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ExperimentError(
                "scientific execution activity row is malformed"
            ) from exc


@dataclass(frozen=True, slots=True)
class ScientificExecutionActivityTerminal:
    sequence: int
    kind: ScientificExecutionTerminalKind
    occurred_at: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 0
        ):
            raise ExperimentError("scientific activity terminal sequence is invalid")
        if not isinstance(self.kind, ScientificExecutionTerminalKind):
            try:
                object.__setattr__(
                    self,
                    "kind",
                    ScientificExecutionTerminalKind(self.kind),
                )
            except (TypeError, ValueError) as exc:
                raise ExperimentError(
                    "scientific activity terminal kind is invalid"
                ) from exc
        if not isinstance(self.occurred_at, str) or not self.occurred_at.endswith("Z"):
            raise ExperimentError("scientific activity terminal time must be UTC")
        try:
            parsed = datetime.fromisoformat(self.occurred_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ExperimentError("scientific activity terminal time is malformed") from exc
        if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
            raise ExperimentError("scientific activity terminal time must be UTC")

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "kind": self.kind.value,
            "occurred_at": self.occurred_at,
        }

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> "ScientificExecutionActivityTerminal":
        if not isinstance(value, Mapping) or set(value) != {
            "sequence",
            "kind",
            "occurred_at",
        }:
            raise ExperimentError("scientific activity terminal is invalid")
        try:
            return cls(
                sequence=value["sequence"],
                kind=ScientificExecutionTerminalKind(value["kind"]),
                occurred_at=value["occurred_at"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ExperimentError("scientific activity terminal is malformed") from exc


@dataclass(frozen=True, slots=True)
class ScientificExecutionActivity:
    """Backend-captured activity whose completeness is authenticated elsewhere.

    This artifact has no scientific authority on its own.  Only a production
    backend verifier installed in the closed scientific-execution dispatcher
    can authenticate its exhaustiveness and bind it into a v2 execution
    authority.
    """

    activity_id: str
    ledger_run_id: str
    execution_run_id: str
    preparation_artifact_sha256: str
    preparation_record_hash: str
    frozen_run_spec_artifact_sha256: str
    frozen_run_spec_record_hash: str
    output_manifest_artifact_sha256: str
    output_manifest_record_hash: str
    capture_profile: str
    activity_rows: tuple[ScientificExecutionActivityRow, ...]
    terminal: ScientificExecutionActivityTerminal

    def __post_init__(self) -> None:
        for name in ("activity_id", "ledger_run_id", "execution_run_id"):
            validate_identifier(getattr(self, name), name.replace("_", " "))
        for name in (
            "preparation_artifact_sha256",
            "preparation_record_hash",
            "frozen_run_spec_artifact_sha256",
            "frozen_run_spec_record_hash",
            "output_manifest_artifact_sha256",
            "output_manifest_record_hash",
        ):
            validate_sha256(getattr(self, name), name.replace("_", " "))
        if self.capture_profile != COMPLETE_GENERIC_ML_ACTIVITY_PROFILE:
            raise ExperimentError("unsupported scientific activity capture profile")
        if (
            not isinstance(self.activity_rows, tuple)
            or not self.activity_rows
            or len(self.activity_rows) > MAX_OUTPUT_ARTIFACTS
            or not all(
                isinstance(row, ScientificExecutionActivityRow)
                for row in self.activity_rows
            )
        ):
            raise ExperimentError("scientific execution activity rows are invalid")
        if tuple(row.sequence for row in self.activity_rows) != tuple(
            range(len(self.activity_rows))
        ):
            raise ExperimentError(
                "scientific execution activity rows must be contiguous and ordered"
            )
        if (
            not isinstance(self.terminal, ScientificExecutionActivityTerminal)
            or self.terminal.sequence != len(self.activity_rows)
        ):
            raise ExperimentError("scientific activity terminal is not final")
        produced = tuple(
            binding.artifact_sha256
            for row in self.activity_rows
            for binding in row.output_artifact_bindings
        )
        if len(set(produced)) != len(produced):
            raise ExperimentError(
                "scientific execution activity has duplicate output producers"
            )
        if len(self.source_artifact_hashes) > MAX_ARTIFACT_PARENTS:
            raise ExperimentError(
                "scientific execution activity exceeds the parent bound"
            )

    @property
    def source_artifact_hashes(self) -> tuple[str, ...]:
        ordered = [
            self.preparation_artifact_sha256,
            self.frozen_run_spec_artifact_sha256,
            self.output_manifest_artifact_sha256,
        ]
        for row in self.activity_rows:
            for binding in row.artifact_bindings:
                if binding.artifact_sha256 not in ordered:
                    ordered.append(binding.artifact_sha256)
        return tuple(ordered)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCIENTIFIC_EXECUTION_ACTIVITY_SCHEMA,
            "activity_id": self.activity_id,
            "ledger_run_id": self.ledger_run_id,
            "execution_run_id": self.execution_run_id,
            "preparation_artifact_sha256": self.preparation_artifact_sha256,
            "preparation_record_hash": self.preparation_record_hash,
            "frozen_run_spec_artifact_sha256": (
                self.frozen_run_spec_artifact_sha256
            ),
            "frozen_run_spec_record_hash": self.frozen_run_spec_record_hash,
            "output_manifest_artifact_sha256": (
                self.output_manifest_artifact_sha256
            ),
            "output_manifest_record_hash": self.output_manifest_record_hash,
            "capture_profile": self.capture_profile,
            "activity_rows": [row.to_dict() for row in self.activity_rows],
            "terminal": self.terminal.to_dict(),
        }

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> "ScientificExecutionActivity":
        expected = set(cls.__dataclass_fields__) | {"schema_version"}
        if (
            not isinstance(value, Mapping)
            or set(value) != expected
            or value.get("schema_version") != SCIENTIFIC_EXECUTION_ACTIVITY_SCHEMA
        ):
            raise ExperimentError("scientific execution activity schema is invalid")
        try:
            arguments = {name: value[name] for name in cls.__dataclass_fields__}
            arguments["activity_rows"] = tuple(
                ScientificExecutionActivityRow.from_mapping(row)
                for row in arguments["activity_rows"]
            )
            arguments["terminal"] = ScientificExecutionActivityTerminal.from_mapping(
                arguments["terminal"]
            )
            return cls(**arguments)
        except (KeyError, TypeError, ValueError) as exc:
            raise ExperimentError("scientific execution activity is malformed") from exc


@dataclass(frozen=True, slots=True)
class ScientificExecutionPreparation:
    preparation_id: str
    ledger_run_id: str
    execution_run_id: str
    ledger_path: str
    frozen_run_spec_artifact_sha256: str
    frozen_run_spec_record_hash: str
    frozen_run_spec_sha256: str
    scientific_binding_sha256: str
    execution_plan_artifact_sha256: str
    execution_plan_record_hash: str
    execution_plan_sha256: str
    execution_input_binding_artifact_sha256: str
    execution_input_binding_record_hash: str
    input_artifact_sha256s: tuple[str, ...]
    input_artifact_record_hashes: tuple[str, ...]
    backend_profile: ScientificBackendAttestationProfile
    challenge_nonce: str
    ledger_event_id: str
    ledger_event_hash: str
    ledger_event_index: int
    ledger_prefix_head_hash: str
    authority_scope: str = "PROSPECTIVE_PROTOCOL_ONLY"
    scientific_evidence: bool = False

    def __post_init__(self) -> None:
        for name in (
            "preparation_id",
            "ledger_run_id",
            "execution_run_id",
            "ledger_event_id",
        ):
            validate_identifier(getattr(self, name), name.replace("_", " "))
        object.__setattr__(
            self,
            "ledger_path",
            _relative_path(self.ledger_path, "scientific execution ledger path"),
        )
        for name in (
            "frozen_run_spec_artifact_sha256",
            "frozen_run_spec_record_hash",
            "frozen_run_spec_sha256",
            "scientific_binding_sha256",
            "execution_plan_artifact_sha256",
            "execution_plan_record_hash",
            "execution_plan_sha256",
            "execution_input_binding_artifact_sha256",
            "execution_input_binding_record_hash",
            "ledger_event_hash",
            "ledger_prefix_head_hash",
        ):
            validate_sha256(getattr(self, name), name.replace("_", " "))
        if (
            not isinstance(self.input_artifact_sha256s, tuple)
            or len(self.input_artifact_sha256s) != 4
            or len(set(self.input_artifact_sha256s)) != 4
            or not isinstance(self.input_artifact_record_hashes, tuple)
            or len(self.input_artifact_record_hashes) != 4
            or len(set(self.input_artifact_record_hashes)) != 4
        ):
            raise ExperimentError(
                "scientific execution preparation requires four exact inputs"
            )
        for value in (
            *self.input_artifact_sha256s,
            *self.input_artifact_record_hashes,
        ):
            validate_sha256(value, "scientific execution input identity")
        if not isinstance(self.backend_profile, ScientificBackendAttestationProfile):
            raise ExperimentError(
                "scientific execution preparation requires a typed backend profile"
            )
        if (
            not isinstance(self.challenge_nonce, str)
            or len(self.challenge_nonce) != 64
            or any(character not in "0123456789abcdef" for character in self.challenge_nonce)
        ):
            raise ExperimentError("scientific execution challenge nonce is invalid")
        if (
            isinstance(self.ledger_event_index, bool)
            or not isinstance(self.ledger_event_index, int)
            or self.ledger_event_index < 0
            or self.ledger_prefix_head_hash != self.ledger_event_hash
            or self.authority_scope != "PROSPECTIVE_PROTOCOL_ONLY"
            or self.scientific_evidence is not False
        ):
            raise ExperimentError(
                "scientific execution preparation exceeds prospective scope"
            )

    @property
    def source_artifact_hashes(self) -> tuple[str, ...]:
        return (
            self.frozen_run_spec_artifact_sha256,
            self.execution_plan_artifact_sha256,
            self.execution_input_binding_artifact_sha256,
            *self.input_artifact_sha256s,
        )

    def to_dict(self) -> dict[str, Any]:
        result = {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if name != "backend_profile"
        }
        result["schema_version"] = SCIENTIFIC_EXECUTION_PREPARATION_SCHEMA
        result["input_artifact_sha256s"] = list(self.input_artifact_sha256s)
        result["input_artifact_record_hashes"] = list(
            self.input_artifact_record_hashes
        )
        result["backend_profile"] = self.backend_profile.to_dict()
        return result

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> "ScientificExecutionPreparation":
        expected = set(cls.__dataclass_fields__) | {"schema_version"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ExperimentError("scientific execution preparation schema is invalid")
        if value["schema_version"] != SCIENTIFIC_EXECUTION_PREPARATION_SCHEMA:
            raise ExperimentError(
                "unsupported scientific execution preparation schema"
            )
        try:
            arguments = {name: value[name] for name in cls.__dataclass_fields__}
            arguments["input_artifact_sha256s"] = tuple(
                arguments["input_artifact_sha256s"]
            )
            arguments["input_artifact_record_hashes"] = tuple(
                arguments["input_artifact_record_hashes"]
            )
            arguments["backend_profile"] = (
                ScientificBackendAttestationProfile.from_mapping(
                    arguments["backend_profile"]
                )
            )
            return cls(**arguments)
        except (KeyError, TypeError, ValueError) as exc:
            raise ExperimentError(
                "scientific execution preparation is malformed"
            ) from exc


@dataclass(frozen=True, slots=True)
class ScientificExecutionAuthority:
    authority_id: str
    ledger_run_id: str
    execution_run_id: str
    ledger_path: str
    preparation_artifact_sha256: str
    preparation_record_hash: str
    frozen_run_spec_artifact_sha256: str
    frozen_run_spec_sha256: str
    scientific_binding_sha256: str
    execution_plan_artifact_sha256: str
    execution_input_binding_artifact_sha256: str
    output_manifest_artifact_sha256: str
    output_manifest_record_hash: str
    environment_artifact_sha256: str
    environment_record_hash: str
    isolation_attestation_artifact_sha256: str
    isolation_attestation_record_hash: str
    backend_attestation_artifact_sha256: str
    backend_attestation_record_hash: str
    backend_profile: ScientificBackendAttestationProfile
    backend_job_id: str
    provider_invocation_id: str
    challenge_nonce: str
    backend_claim_sha256: str
    output_artifact_sha256s: tuple[str, ...]
    output_artifact_record_hashes: tuple[str, ...]
    environment_fingerprint: str
    isolation_policy_sha256: str
    attested_started_at: str
    attested_completed_at: str
    outcome: ScientificExecutionOutcome
    network_used: bool
    cache_used: bool
    checkpoint_used: bool
    resumed_from_checkpoint: bool
    ledger_event_id: str
    ledger_event_hash: str
    ledger_event_index: int
    ledger_prefix_head_hash: str
    execution_activity_artifact_sha256: str | None = None
    execution_activity_record_hash: str | None = None
    verification_status: ScientificExecutionVerificationStatus = (
        ScientificExecutionVerificationStatus.VERIFIED
    )
    authority_scope: str = "SCIENTIFIC_EXECUTION_ATTESTATION"

    def __post_init__(self) -> None:
        for name in (
            "authority_id",
            "ledger_run_id",
            "execution_run_id",
            "backend_job_id",
            "provider_invocation_id",
            "ledger_event_id",
        ):
            validate_identifier(getattr(self, name), name.replace("_", " "))
        object.__setattr__(
            self,
            "ledger_path",
            _relative_path(self.ledger_path, "scientific execution ledger path"),
        )
        for name in (
            "preparation_artifact_sha256",
            "preparation_record_hash",
            "frozen_run_spec_artifact_sha256",
            "frozen_run_spec_sha256",
            "scientific_binding_sha256",
            "execution_plan_artifact_sha256",
            "execution_input_binding_artifact_sha256",
            "output_manifest_artifact_sha256",
            "output_manifest_record_hash",
            "environment_artifact_sha256",
            "environment_record_hash",
            "isolation_attestation_artifact_sha256",
            "isolation_attestation_record_hash",
            "backend_attestation_artifact_sha256",
            "backend_attestation_record_hash",
            "backend_claim_sha256",
            "environment_fingerprint",
            "isolation_policy_sha256",
            "ledger_event_hash",
            "ledger_prefix_head_hash",
        ):
            validate_sha256(getattr(self, name), name.replace("_", " "))
        if (self.execution_activity_artifact_sha256 is None) != (
            self.execution_activity_record_hash is None
        ):
            raise ExperimentError(
                "scientific execution activity artifact binding is incomplete"
            )
        if self.execution_activity_artifact_sha256 is not None:
            validate_sha256(
                self.execution_activity_artifact_sha256,
                "scientific execution activity SHA-256",
            )
            assert self.execution_activity_record_hash is not None
            validate_sha256(
                self.execution_activity_record_hash,
                "scientific execution activity record hash",
            )
        if (
            not isinstance(self.backend_profile, ScientificBackendAttestationProfile)
            or not isinstance(self.output_artifact_sha256s, tuple)
            or not isinstance(self.output_artifact_record_hashes, tuple)
            or len(self.output_artifact_sha256s)
            != len(self.output_artifact_record_hashes)
            or len(set(self.output_artifact_sha256s))
            != len(self.output_artifact_sha256s)
            or len(self.output_artifact_sha256s) > MAX_OUTPUT_ARTIFACTS
        ):
            raise ExperimentError("scientific execution output closure is invalid")
        for value in (
            *self.output_artifact_sha256s,
            *self.output_artifact_record_hashes,
        ):
            validate_sha256(value, "scientific execution output identity")
        if len(self.source_artifact_hashes) > MAX_ARTIFACT_PARENTS:
            raise ExperimentError(
                "scientific execution authority exceeds the registry parent bound"
            )
        if len(set(self.source_artifact_hashes)) != len(
            self.source_artifact_hashes
        ):
            raise ExperimentError(
                "scientific execution authority source artifacts are aliased"
            )
        if (
            not isinstance(self.challenge_nonce, str)
            or len(self.challenge_nonce) != 64
            or any(character not in "0123456789abcdef" for character in self.challenge_nonce)
        ):
            raise ExperimentError("scientific execution challenge nonce is invalid")
        parsed_timestamps: list[datetime] = []
        for name in ("attested_started_at", "attested_completed_at"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.endswith("Z"):
                raise ExperimentError(f"{name} must be a UTC timestamp")
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ExperimentError(f"{name} is malformed") from exc
            if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
                raise ExperimentError(f"{name} must be UTC")
            parsed_timestamps.append(parsed)
        if parsed_timestamps[0] > parsed_timestamps[1]:
            raise ExperimentError("scientific execution timestamps are reversed")
        for name in (
            "network_used",
            "cache_used",
            "checkpoint_used",
            "resumed_from_checkpoint",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ExperimentError(f"{name} must be boolean")
        if not isinstance(self.outcome, ScientificExecutionOutcome):
            try:
                object.__setattr__(
                    self, "outcome", ScientificExecutionOutcome(self.outcome)
                )
            except (TypeError, ValueError) as exc:
                raise ExperimentError("scientific execution outcome is invalid") from exc
        if not isinstance(
            self.verification_status, ScientificExecutionVerificationStatus
        ):
            try:
                object.__setattr__(
                    self,
                    "verification_status",
                    ScientificExecutionVerificationStatus(self.verification_status),
                )
            except (TypeError, ValueError) as exc:
                raise ExperimentError(
                    "scientific execution verification status is invalid"
                ) from exc
        if (
            self.verification_status
            is not ScientificExecutionVerificationStatus.VERIFIED
            or self.authority_scope != "SCIENTIFIC_EXECUTION_ATTESTATION"
            or isinstance(self.ledger_event_index, bool)
            or not isinstance(self.ledger_event_index, int)
            or self.ledger_event_index < 0
        ):
            raise ExperimentError("scientific execution authority is not verified")

    @property
    def scientific_evidence_eligible(self) -> bool:
        return (
            self.verification_status
            is ScientificExecutionVerificationStatus.VERIFIED
            and self.outcome is ScientificExecutionOutcome.COMPLETED
        )

    @property
    def source_artifact_hashes(self) -> tuple[str, ...]:
        result = (
            self.preparation_artifact_sha256,
            self.frozen_run_spec_artifact_sha256,
            self.execution_plan_artifact_sha256,
            self.execution_input_binding_artifact_sha256,
            self.output_manifest_artifact_sha256,
            *self.output_artifact_sha256s,
            self.environment_artifact_sha256,
            self.isolation_attestation_artifact_sha256,
        )
        if self.execution_activity_artifact_sha256 is not None:
            result += (self.execution_activity_artifact_sha256,)
        return (*result, self.backend_attestation_artifact_sha256)

    def to_dict(self) -> dict[str, Any]:
        result = {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if name not in {"backend_profile", "outcome", "verification_status"}
        }
        if self.execution_activity_artifact_sha256 is None:
            result.pop("execution_activity_artifact_sha256")
            result.pop("execution_activity_record_hash")
            result["schema_version"] = SCIENTIFIC_EXECUTION_AUTHORITY_SCHEMA
        else:
            result["schema_version"] = SCIENTIFIC_EXECUTION_AUTHORITY_SCHEMA_V2
        result["backend_profile"] = self.backend_profile.to_dict()
        result["output_artifact_sha256s"] = list(self.output_artifact_sha256s)
        result["output_artifact_record_hashes"] = list(
            self.output_artifact_record_hashes
        )
        result["outcome"] = self.outcome.value
        result["verification_status"] = self.verification_status.value
        return result

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> "ScientificExecutionAuthority":
        if not isinstance(value, Mapping):
            raise ExperimentError("scientific execution authority schema is invalid")
        schema = value.get("schema_version")
        current = set(cls.__dataclass_fields__) | {"schema_version"}
        expected = (
            current
            if schema == SCIENTIFIC_EXECUTION_AUTHORITY_SCHEMA_V2
            else current
            - {
                "execution_activity_artifact_sha256",
                "execution_activity_record_hash",
            }
        )
        if set(value) != expected or schema not in {
            SCIENTIFIC_EXECUTION_AUTHORITY_SCHEMA,
            SCIENTIFIC_EXECUTION_AUTHORITY_SCHEMA_V2,
        }:
            raise ExperimentError("unsupported scientific execution authority schema")
        try:
            arguments = {
                name: value.get(name)
                for name in cls.__dataclass_fields__
                if name not in {"verification_status", "authority_scope"}
            }
            arguments["verification_status"] = value["verification_status"]
            arguments["authority_scope"] = value["authority_scope"]
            arguments["backend_profile"] = (
                ScientificBackendAttestationProfile.from_mapping(
                    arguments["backend_profile"]
                )
            )
            arguments["output_artifact_sha256s"] = tuple(
                arguments["output_artifact_sha256s"]
            )
            arguments["output_artifact_record_hashes"] = tuple(
                arguments["output_artifact_record_hashes"]
            )
            arguments["outcome"] = ScientificExecutionOutcome(
                arguments["outcome"]
            )
            arguments["verification_status"] = (
                ScientificExecutionVerificationStatus(
                    arguments["verification_status"]
                )
            )
            return cls(**arguments)
        except (KeyError, TypeError, ValueError) as exc:
            raise ExperimentError("scientific execution authority is malformed") from exc


@dataclass(frozen=True, slots=True)
class ScientificExecutionAuthorityResolution:
    status: ScientificExecutionVerificationStatus
    reason_code: str
    reason: str
    preparation_artifact_sha256: str
    authority_artifact_sha256: str | None = None
    authority: ScientificExecutionAuthority | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ScientificExecutionVerificationStatus):
            try:
                object.__setattr__(
                    self,
                    "status",
                    ScientificExecutionVerificationStatus(self.status),
                )
            except (TypeError, ValueError) as exc:
                raise ExperimentError(
                    "scientific execution resolution status is invalid"
                ) from exc
        object.__setattr__(
            self,
            "reason_code",
            _bounded_text(self.reason_code, "scientific execution reason code", 256),
        )
        object.__setattr__(
            self,
            "reason",
            _bounded_text(self.reason, "scientific execution reason", 8192),
        )
        validate_sha256(
            self.preparation_artifact_sha256,
            "scientific execution preparation SHA-256",
        )
        if self.authority_artifact_sha256 is not None:
            validate_sha256(
                self.authority_artifact_sha256,
                "scientific execution authority SHA-256",
            )
        if self.status is ScientificExecutionVerificationStatus.VERIFIED:
            if (
                self.authority_artifact_sha256 is None
                or not isinstance(self.authority, ScientificExecutionAuthority)
            ):
                raise ExperimentError(
                    "verified scientific execution resolution lacks authority"
                )
        elif self.authority_artifact_sha256 is not None or self.authority is not None:
            raise ExperimentError(
                "blocked scientific execution resolution cannot carry authority"
            )

    @property
    def scientific_evidence_eligible(self) -> bool:
        return bool(
            self.status is ScientificExecutionVerificationStatus.VERIFIED
            and self.authority is not None
            and self.authority.scientific_evidence_eligible
        )


def _validate_scientific_execution_runtime_identity(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    run_id: str,
) -> None:
    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise ExperimentError(
            "scientific execution requires exact ArtifactRegistry and EventLedger"
        )
    validate_identifier(run_id, "scientific execution ledger run ID")
    if (
        registry.policy.root != ledger.policy.root
        or registry.base_path.name != "registry"
        or ledger.relative_path.name != "events.jsonl"
        or registry.base_path.parent != ledger.relative_path.parent
    ):
        raise ExperimentError(
            "scientific execution requires the canonical paired registry and ledger"
        )


def _locked_scientific_execution_snapshot(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    run_id: str,
) -> tuple[RegistryValidationResult, LedgerValidationResult]:
    """Capture one registry->ledger co-locked scientific source snapshot."""

    _validate_scientific_execution_runtime_identity(registry, ledger, run_id)
    # Materialize both lock paths before nesting.  Creating either lock file
    # while the other namespace is pinned would itself change that snapshot.
    try:
        registry.verify_all(raise_on_error=True)
        ledger.assert_valid()
    except Exception as exc:
        raise ExperimentError(
            "scientific execution registry or ledger cannot be verified"
        ) from exc
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            registry_snapshot = registry._verify_all_locked(
                registry_guard,
                raise_on_error=True,
            )
            ledger_snapshot = ledger._validate_bytes(
                ledger._read_raw_locked(ledger_guard)
            )
            if not ledger_snapshot.valid:
                raise ExperimentError("scientific execution ledger is invalid")
        finally:
            ledger._unlock(ledger_guard)
    except ExperimentError:
        raise
    except Exception as exc:
        raise ExperimentError(
            "scientific execution registry or ledger cannot be verified"
        ) from exc
    finally:
        registry._unlock_mutation(registry_guard)
    if ledger_snapshot.events and any(
        event.run_id != run_id for event in ledger_snapshot.events
    ):
        raise ExperimentError("scientific execution ledger names another run")
    return registry_snapshot, ledger_snapshot


def _require_scientific_execution_snapshot_unchanged(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    run_id: str,
    expected_registry: RegistryValidationResult,
    expected_ledger: LedgerValidationResult,
) -> None:
    current_registry, current_ledger = _locked_scientific_execution_snapshot(
        registry,
        ledger,
        run_id,
    )
    if current_registry != expected_registry or current_ledger != expected_ledger:
        raise ExperimentError(
            "scientific execution sources changed during fresh replay"
        )


def _require_scientific_execution_runtime(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    run_id: str,
) -> tuple[LedgerEvent, ...]:
    _, snapshot = _locked_scientific_execution_snapshot(registry, ledger, run_id)
    return snapshot.events


def _require_scientific_execution_capacity(
    registry_snapshot: RegistryValidationResult,
    ledger_snapshot: LedgerValidationResult,
    *,
    registry_records_needed: int,
    ledger_events_needed: int,
) -> None:
    """Reserve bounded-store capacity before the first admission mutation."""

    if (
        type(registry_records_needed) is not int
        or type(ledger_events_needed) is not int
        or registry_records_needed < 0
        or ledger_events_needed < 0
    ):
        raise ExperimentError("scientific execution capacity request is invalid")
    if registry_snapshot.count + registry_records_needed > MAX_REGISTRY_RECORDS:
        raise ExperimentError("scientific execution registry capacity is insufficient")
    if ledger_snapshot.event_count + ledger_events_needed > MAX_LEDGER_EVENTS:
        raise ExperimentError("scientific execution ledger event capacity is insufficient")
    if (
        ledger_snapshot.valid_prefix_bytes
        + ledger_events_needed * _MAX_SCIENTIFIC_EXECUTION_LEDGER_EVENT_BYTES
        > MAX_LEDGER_BYTES
    ):
        raise ExperimentError("scientific execution ledger byte capacity is insufficient")


def _require_scientific_execution_event_bound(event: LedgerEvent) -> None:
    if (
        len(canonical_json_bytes(event.to_dict()) + b"\n")
        > _MAX_SCIENTIFIC_EXECUTION_LEDGER_EVENT_BYTES
    ):
        raise ExperimentError("scientific execution event exceeds its reserved bound")


def _load_scientific_execution_json(
    registry: ArtifactRegistry,
    digest: str,
    *,
    logical_type: str,
    creator_role: Role,
    schema_version: str = "1.0",
) -> tuple[ArtifactRecord, Mapping[str, Any], bytes]:
    validate_sha256(digest, f"{logical_type} SHA-256")
    try:
        registry.verify(digest, raise_on_error=True)
        record = registry.get_metadata(digest)
        raw = registry.get_bytes(digest)
        value = safe_json_loads(raw)
    except (ArtifactError, ValidationError) as exc:
        raise ExperimentError(f"{logical_type} cannot be reopened") from exc
    if (
        record.logical_type != logical_type
        or record.creator_role is not creator_role
        or record.schema_version != schema_version
        or record.mime_type != "application/json"
        or record.validation_result != "PASS"
        or not record.frozen
        or not isinstance(value, Mapping)
        or raw != canonical_json_bytes(value) + b"\n"
    ):
        raise ExperimentError(f"{logical_type} metadata or bytes are not authoritative")
    return record, value, raw


def _require_scientific_execution_input_records(
    registry: ArtifactRegistry,
    spec: FrozenRunSpec,
) -> tuple[ArtifactRecord, ...]:
    """Replay exactly the four ordinary execution inputs, in wire order."""

    identities = (
        (spec.code_sha256, "experiment_code", Role.IMPLEMENTER),
        (spec.data_sha256, "experiment_dataset", Role.EVIDENCE_CURATOR),
        (
            spec.configuration_sha256,
            "experiment_configuration",
            Role.PROTOCOL_DESIGNER,
        ),
        (
            spec.evaluator_sha256,
            "evaluator_implementation",
            Role.PROTOCOL_DESIGNER,
        ),
    )
    records: list[ArtifactRecord] = []
    for digest, logical_type, role in identities:
        try:
            registry.verify(digest, raise_on_error=True)
            record = registry.get_metadata(digest)
            raw = registry.get_bytes(digest)
        except (ArtifactError, ValidationError) as exc:
            raise ExperimentError(
                "scientific execution input cannot be independently reopened"
            ) from exc
        if (
            record.sha256 != digest
            or record.logical_type != logical_type
            or record.creator_role is not role
            or record.validation_result != "PASS"
            or not record.frozen
            or record.size != len(raw)
            or hashlib.sha256(raw).hexdigest() != digest
        ):
            raise ExperimentError(
                "scientific execution input metadata or exact bytes are substituted"
            )
        records.append(record)
    return tuple(records)


def _require_scientific_execution_spec_and_inputs(
    registry: ArtifactRegistry,
    frozen_run_spec_artifact_sha256: str,
) -> tuple[ArtifactRecord, FrozenRunSpec, tuple[ArtifactRecord, ...]]:
    from .scientific_design import ScientificDesignError
    from .scientific_numeric_ablation import resolve_scientific_numeric_ablation_binding

    spec_record, spec_value, _ = _load_scientific_execution_json(
        registry,
        frozen_run_spec_artifact_sha256,
        logical_type="frozen_run_spec",
        creator_role=Role.EXPERIMENT_RUNNER,
    )
    if (
        spec_record.origin
        != "run spec frozen after scientific-plan admission and before execution"
        or spec_record.creation_command != ("scientist-one", "freeze-run-spec")
    ):
        raise ExperimentError(
            "scientific execution requires the source-owned frozen run spec"
        )
    spec = _parse_frozen_run_spec(spec_value)
    if (
        spec.evidence_class is not EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE
        or spec.network_allowed
        or spec.shell_allowed
        or spec.attempt != 1
        or spec.retry_of_run_id is not None
    ):
        raise ExperimentError(
            "scientific execution spec is not a fresh isolated evidentiary attempt"
        )
    input_records = _require_scientific_execution_input_records(registry, spec)
    method_binding = resolve_scientific_method_definition_binding(
        registry,
        spec=spec,
    )
    if not spec_record.parent_artifacts:
        raise ExperimentError("scientific execution spec omits its contract parent")
    try:
        statistical_binding = resolve_scientific_statistical_use_binding(
            registry, spec=spec,
            expected_contract_artifact_sha256=spec_record.parent_artifacts[0],
        )
        reference_binding = resolve_scientific_reference_work_binding(
            registry, spec=spec,
            expected_contract_artifact_sha256=spec_record.parent_artifacts[0],
        )
        resolve_scientific_numeric_ablation_binding(
            registry, spec=spec,
            expected_contract_artifact_sha256=spec_record.parent_artifacts[0],
        )
    except ScientificDesignError as exc:
        # A concurrent publisher can invalidate a full contract-lineage read.
        # Keep that refusal and its cause within the execution API's error
        # boundary; never retry here or reuse a partially validated binding.
        raise ExperimentError(
            "scientific execution prospective source validation failed"
        ) from exc
    expected_parent_tail = (
        *(
            (method_binding.method_definition_artifact_sha256,)
            if method_binding is not None
            else ()
        ),
        *((statistical_binding.artifact_hash,) if statistical_binding is not None else ()),
        *(record.sha256 for record in input_records),
    )
    if (
        len(spec_record.parent_artifacts) < 2 + len(expected_parent_tail)
        or spec_record.parent_artifacts[-len(expected_parent_tail) :]
        != expected_parent_tail
    ):
        raise ExperimentError(
            "scientific execution run spec lacks exact ordered Method/input parents"
        )
    if reference_binding is not None:
        _require_scientific_reference_work_source_chronology(
            (
                *reference_binding.source_records,
                *(registry.get_metadata(digest) for digest in spec_record.parent_artifacts),
            ),
            timestamp=spec_record.created_at,
        )
    return spec_record, spec, input_records


def require_scientific_execution_run_spec(
    registry: ArtifactRegistry,
    *,
    frozen_run_spec_artifact_sha256: str,
) -> FrozenRunSpec:
    """Freshly reopen one evidentiary run spec and its four immutable inputs.

    This read-only source-owner seam exists so a prospective clean-rerun plan
    can bind the second attempt *before* its execution preparation is created.
    It never confers execution authority.
    """

    if type(registry) is not ArtifactRegistry:
        raise ExperimentError(
            "scientific execution run-spec replay requires exact ArtifactRegistry"
        )
    _record, spec, _inputs = _require_scientific_execution_spec_and_inputs(
        registry,
        frozen_run_spec_artifact_sha256,
    )
    return spec


def require_scientific_execution_activity(
    registry: ArtifactRegistry,
    *,
    activity_artifact_sha256: str,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    expected_preparation_artifact_sha256: str,
    expected_frozen_run_spec_artifact_sha256: str,
    expected_output_manifest_artifact_sha256: str,
) -> ScientificExecutionActivity:
    """Replay one exact activity log without granting execution authority.

    This validates canonical custody and internal completeness.  It does not
    establish that the log is exhaustive: only a backend profile in the
    closed production verifier map can authenticate that property.
    """

    if type(registry) is not ArtifactRegistry:
        raise ExperimentError(
            "scientific execution activity replay requires exact ArtifactRegistry"
        )
    validate_identifier(expected_ledger_run_id, "expected ledger run ID")
    validate_identifier(expected_execution_run_id, "expected execution run ID")
    activity_record, value, _ = _load_scientific_execution_json(
        registry,
        activity_artifact_sha256,
        logical_type=SCIENTIFIC_EXECUTION_ACTIVITY_LOGICAL_TYPE,
        creator_role=Role.EXPERIMENT_RUNNER,
    )
    if (
        activity_record.origin != _SCIENTIFIC_EXECUTION_ACTIVITY_ORIGIN
        or activity_record.creation_command != _SCIENTIFIC_EXECUTION_ACTIVITY_COMMAND
    ):
        raise ExperimentError(
            "scientific execution activity metadata is not backend-owned"
        )
    activity = ScientificExecutionActivity.from_mapping(value)
    preparation_record, preparation_value, _ = _load_scientific_execution_json(
        registry,
        expected_preparation_artifact_sha256,
        logical_type=SCIENTIFIC_EXECUTION_PREPARATION_LOGICAL_TYPE,
        creator_role=Role.CLAIM_VERIFIER,
    )
    preparation = ScientificExecutionPreparation.from_mapping(preparation_value)
    spec_record, spec, _ = _require_scientific_execution_spec_and_inputs(
        registry,
        expected_frozen_run_spec_artifact_sha256,
    )
    manifest_record, manifest_value, _ = _load_scientific_execution_json(
        registry,
        expected_output_manifest_artifact_sha256,
        logical_type="experiment_output_manifest",
        creator_role=Role.EXPERIMENT_RUNNER,
    )
    manifest = OutputManifest.from_mapping(manifest_value)
    if (
        activity.ledger_run_id != expected_ledger_run_id
        or activity.execution_run_id != expected_execution_run_id
        or activity.preparation_artifact_sha256 != preparation_record.sha256
        or activity.preparation_record_hash != str(preparation_record.record_hash)
        or activity.frozen_run_spec_artifact_sha256 != spec_record.sha256
        or activity.frozen_run_spec_record_hash != str(spec_record.record_hash)
        or activity.output_manifest_artifact_sha256 != manifest_record.sha256
        or activity.output_manifest_record_hash != str(manifest_record.record_hash)
        or preparation.ledger_run_id != expected_ledger_run_id
        or preparation.execution_run_id != expected_execution_run_id
        or preparation.frozen_run_spec_artifact_sha256 != spec_record.sha256
        or spec.run_id != expected_execution_run_id
        or manifest.run_id != spec.run_id
        or manifest.spec_sha256 != spec.sha256
        or manifest_record.parent_artifacts != (spec_record.sha256,)
    ):
        raise ExperimentError(
            "scientific execution activity names another preparation, spec, or manifest"
        )
    bound_records: dict[str, ArtifactRecord] = {}
    for row in activity.activity_rows:
        if row.seed is not None and row.seed not in spec.seeds:
            raise ExperimentError("scientific activity names an unplanned seed")
        if row.ablation_id is not None and row.ablation_id not in spec.required_ablations:
            raise ExperimentError("scientific activity names an unplanned ablation")
        if row.kind in {
            ScientificExecutionActivityKind.MODEL_INVOCATION,
            ScientificExecutionActivityKind.PREDICTION_GENERATION,
        } and (row.seed is None or row.condition_id is None or row.ablation_id is not None):
            raise ExperimentError(
                "model or prediction activity lacks its planned seed and condition"
            )
        if row.kind is ScientificExecutionActivityKind.ABLATION_EXECUTION and (
            row.ablation_id is None
        ):
            raise ExperimentError("ablation activity lacks its planned identity")
        for binding in row.artifact_bindings:
            try:
                registry.verify(binding.artifact_sha256, raise_on_error=True)
                record = registry.get_metadata(binding.artifact_sha256)
            except (ArtifactError, ValidationError) as exc:
                raise ExperimentError(
                    "scientific activity binding cannot be reopened"
                ) from exc
            if (
                record.record_hash is None
                or str(record.record_hash) != binding.artifact_record_hash
                or record.validation_result != "PASS"
                or not record.frozen
            ):
                raise ExperimentError(
                    "scientific activity binding metadata is substituted"
                )
            prior = bound_records.get(record.sha256)
            if prior is not None and prior != record:
                raise ExperimentError(
                    "scientific activity binding changed during replay"
                )
            bound_records[record.sha256] = record
        if row.kind is ScientificExecutionActivityKind.DATASET_READ:
            assert row.dataset_artifact_binding is not None
            assert row.split_artifact_binding is not None
            assert row.dataset_access_purpose is not None
            dataset_record = bound_records[
                row.dataset_artifact_binding.artifact_sha256
            ]
            split_record = bound_records[row.split_artifact_binding.artifact_sha256]
            try:
                split_value = safe_json_loads(registry.get_bytes(split_record.sha256))
            except (ArtifactError, ValidationError) as exc:
                raise ExperimentError(
                    "scientific activity split binding cannot be parsed"
                ) from exc
            expected_role = {
                ScientificDatasetAccessPurpose.TRAIN_FEATURES: "TRAIN",
                ScientificDatasetAccessPurpose.TRAIN_LABELS: "TRAIN",
                ScientificDatasetAccessPurpose.DEVELOPMENT_FEATURES: "DEVELOPMENT",
                ScientificDatasetAccessPurpose.DEVELOPMENT_LABELS: "DEVELOPMENT",
                ScientificDatasetAccessPurpose.VALIDATION_FEATURES: "VALIDATION",
                ScientificDatasetAccessPurpose.VALIDATION_LABELS: "VALIDATION",
                ScientificDatasetAccessPurpose.CONFIRMATORY_FEATURES: "CONFIRMATORY",
                ScientificDatasetAccessPurpose.CONFIRMATORY_LABELS: "CONFIRMATORY",
            }[row.dataset_access_purpose]
            if (
                dataset_record.logical_type != "scientific_dataset_authority"
                or split_record.logical_type
                != "scientific_dataset_split_authority"
                or not isinstance(split_value, Mapping)
                or split_value.get("split_role") != expected_role
                or split_value.get("dataset_authority_artifact_sha256")
                != dataset_record.sha256
            ):
                raise ExperimentError(
                    "scientific activity dataset purpose differs from its source-owned split"
                )
    manifest_hashes = tuple(item.sha256 for item in manifest.artifacts)
    produced_hashes = tuple(
        binding.artifact_sha256
        for row in activity.activity_rows
        for binding in row.output_artifact_bindings
    )
    if (
        len(set(manifest_hashes)) != len(manifest_hashes)
        or set(produced_hashes) != set(manifest_hashes)
        or len(produced_hashes) != len(manifest_hashes)
    ):
        raise ExperimentError(
            "scientific execution activity does not produce the exact manifest closure"
        )
    producer_sequence = {
        binding.artifact_sha256: row.sequence
        for row in activity.activity_rows
        for binding in row.output_artifact_bindings
    }
    if any(
        binding.artifact_sha256 in producer_sequence
        and producer_sequence[binding.artifact_sha256] >= row.sequence
        for row in activity.activity_rows
        for binding in row.input_artifact_bindings
    ):
        raise ExperimentError(
            "scientific execution activity consumes an output before it is produced"
        )
    if activity_record.parent_artifacts != activity.source_artifact_hashes:
        raise ExperimentError(
            "scientific execution activity has substituted or reordered parents"
        )
    activity_time = _scientific_execution_timestamp(
        activity_record.created_at,
        "scientific execution activity artifact time",
    )
    manifest_time = _scientific_execution_timestamp(
        manifest_record.created_at,
        "scientific execution manifest time",
    )
    if activity_time < manifest_time:
        raise ExperimentError(
            "scientific execution activity predates its output manifest"
        )
    return activity


def _scientific_execution_preparation_binding(
    *,
    preparation_id: str,
    ledger_run_id: str,
    spec_record: ArtifactRecord,
    spec: FrozenRunSpec,
    plan_record: ArtifactRecord,
    plan: AdaptiveExecutionPlan,
    input_binding_record: ArtifactRecord,
    input_records: tuple[ArtifactRecord, ...],
    backend_profile: ScientificBackendAttestationProfile,
    challenge_nonce: str,
) -> dict[str, Any]:
    source_records = (
        spec_record,
        plan_record,
        input_binding_record,
        *input_records,
    )
    return {
        "schema_version": SCIENTIFIC_EXECUTION_PREPARATION_EVENT_SCHEMA,
        "kind": "SCIENTIFIC_EXECUTION_PREPARED",
        "preparation_id": preparation_id,
        "ledger_run_id": ledger_run_id,
        "execution_run_id": spec.run_id,
        "frozen_run_spec_artifact_sha256": spec_record.sha256,
        "frozen_run_spec_sha256": spec.sha256,
        "scientific_binding_sha256": spec.scientific_binding_sha256,
        "execution_plan_artifact_sha256": plan_record.sha256,
        "execution_plan_sha256": plan.sha256,
        "execution_input_binding_artifact_sha256": input_binding_record.sha256,
        "input_artifact_sha256s": [record.sha256 for record in input_records],
        "artifact_sha256s": [record.sha256 for record in source_records],
        "artifact_record_hashes": [
            str(record.record_hash) for record in source_records
        ],
        "backend_profile": backend_profile.to_dict(),
        "challenge_nonce": challenge_nonce,
        "authority_scope": "PROSPECTIVE_PROTOCOL_ONLY",
        "scientific_evidence": False,
    }


def _validate_scientific_execution_preparation_event(
    event: LedgerEvent,
    event_index: int,
    events: tuple[LedgerEvent, ...],
    *,
    binding: Mapping[str, Any],
    source_records: tuple[ArtifactRecord, ...],
    spec: FrozenRunSpec,
) -> None:
    if (
        event.event_hash is None
        or event.actor_role is not Role.PROTOCOL_DESIGNER
        or event.event_type != "CHECKPOINT"
        or event.state_before != event.state_after
        or event.artifact_hashes
        != tuple(item.sha256 for item in source_records)
        or event.code_version != f"sha256:{spec.code_sha256}"
        or event.configuration_hash != spec.configuration_sha256
        or event.dataset_identifiers != (spec.data_sha256,)
        or event.random_seeds != spec.seeds
        or event.evaluator_outputs
        or event.reason
        != (
            "froze exact scientific execution inputs, plan, backend profile, "
            "and one-use challenge before dispatch"
        )
        or thaw_json(event.metadata)
        != {"scientific_execution_preparation": dict(binding)}
        or any(
            item.event_type == "CORRECTION"
            and item.supersedes_event_id == event.event_id
            for item in events[event_index + 1 :]
        )
    ):
        raise ExperimentError(
            "scientific execution preparation event is stale or substituted"
        )


def _matching_scientific_execution_preparation_records(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
    *,
    logical_type: str,
    frozen_run_spec_artifact_sha256: str,
    execution_run_id: str,
) -> tuple[ArtifactRecord, ...]:
    """Find every artifact that claims one prospective execution slot."""

    matches: list[ArtifactRecord] = []
    for record in records:
        if record.logical_type != logical_type:
            continue
        try:
            value = safe_json_loads(registry.get_bytes(record.sha256))
        except Exception as exc:
            raise ExperimentError(
                "scientific execution preparation slot cannot be reopened"
            ) from exc
        if not isinstance(value, Mapping):
            raise ExperimentError(
                "scientific execution preparation slot is malformed"
            )
        if (
            frozen_run_spec_artifact_sha256 in record.parent_artifacts
            or value.get("frozen_run_spec_artifact_sha256")
            == frozen_run_spec_artifact_sha256
            or value.get("execution_run_id") == execution_run_id
        ):
            matches.append(record)
    return tuple(matches)


def register_scientific_execution_preparation(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    ledger_run_id: str,
    frozen_run_spec_artifact_sha256: str,
    adaptive_execution_plan: AdaptiveExecutionPlan,
    backend_profile: ScientificBackendAttestationProfile,
) -> ArtifactRecord:
    """Freeze exact scientific inputs and a one-use challenge before dispatch."""

    entry_registry, entry_ledger = _locked_scientific_execution_snapshot(
        registry,
        ledger,
        ledger_run_id,
    )
    from .seed_reporting import (
        OperationalSeedReportingError,
        reject_operational_seed_exposure,
    )

    # Prospective use, not historical preparation/authority readback. The
    # non-isolated operational profile cannot prove other run-local inputs
    # were unread; its publisher reciprocally refuses scientific coexistence.
    # Both publishers compare the full paired source snapshot at commit.
    try:
        reject_operational_seed_exposure(
            registry, entry_registry.records, entry_ledger.events,
            complete_registry_population=True,
        )
    except OperationalSeedReportingError as exc:
        raise ExperimentError(
            "scientific preparation cannot follow operational reservation or possible exposure"
        ) from exc
    if not isinstance(adaptive_execution_plan, AdaptiveExecutionPlan):
        raise ExperimentError(
            "scientific execution preparation requires a typed adaptive plan"
        )
    if not isinstance(backend_profile, ScientificBackendAttestationProfile):
        raise ExperimentError(
            "scientific execution preparation requires a typed backend profile"
        )
    spec_record, spec, input_records = (
        _require_scientific_execution_spec_and_inputs(
            registry,
            frozen_run_spec_artifact_sha256,
        )
    )
    _validate_adaptive_plan_binding(
        adaptive_execution_plan,
        spec.compute_profile,
        spec.resource_estimate,
        pending_tasks=len(spec.seeds),
        bytes_per_sample=spec.bytes_per_sample,
        worker_overhead_bytes=spec.worker_overhead_bytes,
    )
    existing_preparations = _matching_scientific_execution_preparation_records(
        registry,
        entry_registry.records,
        logical_type=SCIENTIFIC_EXECUTION_PREPARATION_LOGICAL_TYPE,
        frozen_run_spec_artifact_sha256=spec_record.sha256,
        execution_run_id=spec.run_id,
    )
    if len(existing_preparations) > 1:
        raise ExperimentError("scientific execution preparation slot is ambiguous")
    if existing_preparations:
        existing = require_scientific_execution_preparation(
            registry,
            ledger,
            preparation_artifact_sha256=existing_preparations[0].sha256,
            expected_ledger_run_id=ledger_run_id,
            expected_execution_run_id=spec.run_id,
        )
        if (
            existing.backend_profile != backend_profile
            or existing.execution_plan_sha256 != adaptive_execution_plan.sha256
        ):
            raise ExperimentError(
                "scientific execution preparation slot already has another plan or backend profile"
            )
        return existing_preparations[0]
    if any(
        record.logical_type
        in {"experiment_output_manifest", SCIENTIFIC_EXECUTION_AUTHORITY_LOGICAL_TYPE}
        and spec_record.sha256 in record.parent_artifacts
        for record in entry_registry.records
    ):
        raise ExperimentError(
            "scientific execution preparation cannot be created after output"
        )
    plan_value = {
        "schema_version": SCIENTIFIC_EXECUTION_PLAN_SCHEMA,
        "ledger_run_id": ledger_run_id,
        "execution_run_id": spec.run_id,
        "frozen_run_spec_artifact_sha256": spec_record.sha256,
        "frozen_run_spec_sha256": spec.sha256,
        "scientific_binding_sha256": spec.scientific_binding_sha256,
        "adaptive_execution_plan": adaptive_execution_plan.to_dict(),
        "backend_profile": backend_profile.to_dict(),
        "authority_scope": "PROSPECTIVE_PROTOCOL_ONLY",
        "scientific_evidence": False,
    }
    plan_bytes = canonical_json_bytes(plan_value) + b"\n"
    plan_sha256 = hashlib.sha256(plan_bytes).hexdigest()
    existing_plans = _matching_scientific_execution_preparation_records(
        registry,
        entry_registry.records,
        logical_type=SCIENTIFIC_EXECUTION_PLAN_LOGICAL_TYPE,
        frozen_run_spec_artifact_sha256=spec_record.sha256,
        execution_run_id=spec.run_id,
    )
    if len(existing_plans) > 1 or (
        existing_plans and existing_plans[0].sha256 != plan_sha256
    ):
        raise ExperimentError(
            "scientific execution preparation plan slot is competing"
        )
    input_binding_value = {
        "schema_version": SCIENTIFIC_EXECUTION_INPUT_BINDING_SCHEMA,
        "ledger_run_id": ledger_run_id,
        "execution_run_id": spec.run_id,
        "frozen_run_spec_artifact_sha256": spec_record.sha256,
        "frozen_run_spec_sha256": spec.sha256,
        "execution_plan_artifact_sha256": plan_sha256,
        "execution_plan_sha256": adaptive_execution_plan.sha256,
        "argv": list(spec.argv),
        "working_directory": spec.working_directory,
        "seeds": list(spec.seeds),
        "inputs": [
            {
                "kind": kind,
                "artifact_sha256": record.sha256,
                "artifact_record_hash": str(record.record_hash),
                "logical_type": record.logical_type,
                "creator_role": record.creator_role.value,
                "size": record.size,
            }
            for kind, record in zip(
                ("code", "data", "configuration", "evaluator"),
                input_records,
                strict=True,
            )
        ],
        "authority_scope": "PROSPECTIVE_PROTOCOL_ONLY",
        "scientific_evidence": False,
    }
    input_binding_bytes = canonical_json_bytes(input_binding_value) + b"\n"
    input_binding_sha256 = hashlib.sha256(input_binding_bytes).hexdigest()
    existing_input_bindings = _matching_scientific_execution_preparation_records(
        registry,
        entry_registry.records,
        logical_type=SCIENTIFIC_EXECUTION_INPUT_BINDING_LOGICAL_TYPE,
        frozen_run_spec_artifact_sha256=spec_record.sha256,
        execution_run_id=spec.run_id,
    )
    if len(existing_input_bindings) > 1 or (
        existing_input_bindings
        and existing_input_bindings[0].sha256 != input_binding_sha256
    ):
        raise ExperimentError(
            "scientific execution input-binding slot is competing"
        )
    admitted: list[tuple[int, LedgerEvent, Mapping[str, Any]]] = []
    for index, candidate_event in enumerate(entry_ledger.events):
        candidate = thaw_json(candidate_event.metadata).get(
            "scientific_execution_preparation"
        )
        if (
            isinstance(candidate, Mapping)
            and candidate.get("execution_run_id") == spec.run_id
        ):
            admitted.append((index, candidate_event, candidate))
    if len(admitted) > 1:
        raise ExperimentError("scientific execution preparation event is ambiguous")
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            locked_registry = registry._verify_all_locked(
                registry_guard,
                raise_on_error=True,
            )
            locked_ledger = ledger._validate_bytes(
                ledger._read_raw_locked(ledger_guard)
            )
            if (
                locked_registry != entry_registry
                or locked_ledger != entry_ledger
                or not locked_ledger.valid
            ):
                raise ExperimentError(
                    "scientific execution sources changed before preparation admission"
                )
            records_needed = (
                int(not existing_plans)
                + int(not existing_input_bindings)
                + 1
            )
            _require_scientific_execution_capacity(
                locked_registry,
                locked_ledger,
                registry_records_needed=records_needed,
                ledger_events_needed=int(not admitted),
            )
            plan_record = registry._put_bytes_locked(
                registry_guard,
                plan_bytes,
                logical_type=SCIENTIFIC_EXECUTION_PLAN_LOGICAL_TYPE,
                origin=_SCIENTIFIC_EXECUTION_PREPARATION_ORIGIN,
                creator_role=Role.PROTOCOL_DESIGNER,
                creation_command=_SCIENTIFIC_EXECUTION_PREPARATION_COMMAND,
                parent_artifacts=(spec_record.sha256,),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=None,
            )
            input_binding_record = registry._put_bytes_locked(
                registry_guard,
                input_binding_bytes,
                logical_type=SCIENTIFIC_EXECUTION_INPUT_BINDING_LOGICAL_TYPE,
                origin=_SCIENTIFIC_EXECUTION_PREPARATION_ORIGIN,
                creator_role=Role.PROTOCOL_DESIGNER,
                creation_command=_SCIENTIFIC_EXECUTION_PREPARATION_COMMAND,
                parent_artifacts=(
                    spec_record.sha256,
                    plan_record.sha256,
                    *(record.sha256 for record in input_records),
                ),
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=None,
            )
            source_records = (
                spec_record,
                plan_record,
                input_binding_record,
                *input_records,
            )
            if admitted:
                event_index, event, admitted_binding = admitted[0]
                challenge_nonce = admitted_binding.get("challenge_nonce")
                preparation_id = admitted_binding.get("preparation_id")
                if not isinstance(challenge_nonce, str) or not isinstance(
                    preparation_id, str
                ):
                    raise ExperimentError(
                        "scientific execution preparation recovery binding is malformed"
                    )
                binding = _scientific_execution_preparation_binding(
                    preparation_id=preparation_id,
                    ledger_run_id=ledger_run_id,
                    spec_record=spec_record,
                    spec=spec,
                    plan_record=plan_record,
                    plan=adaptive_execution_plan,
                    input_binding_record=input_binding_record,
                    input_records=input_records,
                    backend_profile=backend_profile,
                    challenge_nonce=challenge_nonce,
                )
                if dict(admitted_binding) != binding:
                    raise ExperimentError(
                        "scientific execution preparation recovery differs from the admitted event"
                    )
                committed_ledger = locked_ledger
            else:
                challenge_nonce = secrets.token_hex(32)
                preparation_key = hashlib.sha256(
                    canonical_json_bytes(
                        {
                            "ledger_run_id": ledger_run_id,
                            "execution_run_id": spec.run_id,
                            "spec": spec_record.sha256,
                            "plan": plan_record.sha256,
                            "input_binding": input_binding_record.sha256,
                            "backend_profile": backend_profile.to_dict(),
                            "challenge_nonce": challenge_nonce,
                        }
                    )
                ).hexdigest()
                preparation_id = f"scientific-preparation-{preparation_key[:24]}"
                binding = _scientific_execution_preparation_binding(
                    preparation_id=preparation_id,
                    ledger_run_id=ledger_run_id,
                    spec_record=spec_record,
                    spec=spec,
                    plan_record=plan_record,
                    plan=adaptive_execution_plan,
                    input_binding_record=input_binding_record,
                    input_records=input_records,
                    backend_profile=backend_profile,
                    challenge_nonce=challenge_nonce,
                )
                if any(
                    isinstance(
                        candidate := thaw_json(candidate_event.metadata).get(
                            "scientific_execution_preparation"
                        ),
                        Mapping,
                    )
                    and candidate.get("challenge_nonce") == challenge_nonce
                    for candidate_event in locked_ledger.events
                ):
                    raise ExperimentError(
                        "scientific execution preparation challenge was already consumed"
                    )

                def build_preparation_event(
                    current: LedgerValidationResult,
                ) -> LedgerEvent:
                    if current != locked_ledger:
                        raise ExperimentError(
                            "scientific execution ledger changed before preparation admission"
                        )
                    current_state = (
                        current.events[-1].state_after
                        if current.events
                        else MacroState.PREFLIGHT
                    )
                    candidate_event = LedgerEvent.create(
                        run_id=ledger_run_id,
                        actor_role=Role.PROTOCOL_DESIGNER,
                        state_before=current_state,
                        requested_state_after=current_state,
                        artifact_hashes=tuple(
                            record.sha256 for record in source_records
                        ),
                        code_version=f"sha256:{spec.code_sha256}",
                        configuration_hash=spec.configuration_sha256,
                        dataset_identifiers=(spec.data_sha256,),
                        random_seeds=spec.seeds,
                        evaluator_outputs=(),
                        reason=(
                            "froze exact scientific execution inputs, plan, backend profile, "
                            "and one-use challenge before dispatch"
                        ),
                        prior_event_hash=current.head_hash,
                        event_type="CHECKPOINT",
                        metadata={"scientific_execution_preparation": binding},
                    )
                    _require_scientific_execution_event_bound(candidate_event)
                    return candidate_event

                event = ledger._append_locked(
                    ledger_guard,
                    build_preparation_event,
                )
                committed_ledger = ledger._validate_bytes(
                    ledger._read_raw_locked(ledger_guard)
                )
                if not committed_ledger.valid:
                    raise ExperimentError(
                        "scientific execution preparation corrupted the ledger"
                    )
                event_index = len(committed_ledger.events) - 1
            if event.event_hash is None:
                raise ExperimentError(
                    "scientific execution preparation event hash is absent"
                )
            _validate_scientific_execution_preparation_event(
                event,
                event_index,
                committed_ledger.events,
                binding=binding,
                source_records=source_records,
                spec=spec,
            )
            preparation = ScientificExecutionPreparation(
                preparation_id=preparation_id,
                ledger_run_id=ledger_run_id,
                execution_run_id=spec.run_id,
                ledger_path=ledger.relative_path.as_posix(),
                frozen_run_spec_artifact_sha256=spec_record.sha256,
                frozen_run_spec_record_hash=str(spec_record.record_hash),
                frozen_run_spec_sha256=spec.sha256,
                scientific_binding_sha256=spec.scientific_binding_sha256,
                execution_plan_artifact_sha256=plan_record.sha256,
                execution_plan_record_hash=str(plan_record.record_hash),
                execution_plan_sha256=adaptive_execution_plan.sha256,
                execution_input_binding_artifact_sha256=(
                    input_binding_record.sha256
                ),
                execution_input_binding_record_hash=str(
                    input_binding_record.record_hash
                ),
                input_artifact_sha256s=tuple(
                    record.sha256 for record in input_records
                ),
                input_artifact_record_hashes=tuple(
                    str(record.record_hash) for record in input_records
                ),
                backend_profile=backend_profile,
                challenge_nonce=challenge_nonce,
                ledger_event_id=event.event_id,
                ledger_event_hash=event.event_hash,
                ledger_event_index=event_index,
                ledger_prefix_head_hash=event.event_hash,
            )
            record = registry._put_bytes_locked(
                registry_guard,
                canonical_json_bytes(preparation.to_dict()) + b"\n",
                logical_type=SCIENTIFIC_EXECUTION_PREPARATION_LOGICAL_TYPE,
                origin=_SCIENTIFIC_EXECUTION_PREPARATION_ORIGIN,
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=_SCIENTIFIC_EXECUTION_PREPARATION_COMMAND,
                parent_artifacts=preparation.source_artifact_hashes,
                schema_version="1.0",
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=None,
            )
            final_registry = registry._verify_all_locked(
                registry_guard,
                raise_on_error=True,
            )
            final_ledger = ledger._validate_bytes(
                ledger._read_raw_locked(ledger_guard)
            )
            if (
                final_registry.count != locked_registry.count + records_needed
                or final_ledger != committed_ledger
            ):
                raise ExperimentError(
                    "scientific execution preparation changed during admission"
                )
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    require_scientific_execution_preparation(
        registry,
        ledger,
        preparation_artifact_sha256=record.sha256,
        expected_ledger_run_id=ledger_run_id,
        expected_execution_run_id=spec.run_id,
    )
    return record


def require_scientific_execution_preparation(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    preparation_artifact_sha256: str,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
) -> ScientificExecutionPreparation:
    entry_registry, entry_ledger = _locked_scientific_execution_snapshot(
        registry,
        ledger,
        expected_ledger_run_id,
    )
    events = entry_ledger.events
    validate_identifier(expected_execution_run_id, "expected execution run ID")
    record, value, _ = _load_scientific_execution_json(
        registry,
        preparation_artifact_sha256,
        logical_type=SCIENTIFIC_EXECUTION_PREPARATION_LOGICAL_TYPE,
        creator_role=Role.CLAIM_VERIFIER,
    )
    if (
        record.origin != _SCIENTIFIC_EXECUTION_PREPARATION_ORIGIN
        or record.creation_command != _SCIENTIFIC_EXECUTION_PREPARATION_COMMAND
    ):
        raise ExperimentError(
            "scientific execution preparation metadata is not source-owned"
        )
    preparation = ScientificExecutionPreparation.from_mapping(value)
    if (
        preparation.ledger_run_id != expected_ledger_run_id
        or preparation.execution_run_id != expected_execution_run_id
        or preparation.ledger_path != ledger.relative_path.as_posix()
        or record.parent_artifacts != preparation.source_artifact_hashes
    ):
        raise ExperimentError("scientific execution preparation names another closure")
    spec_record, spec, input_records = (
        _require_scientific_execution_spec_and_inputs(
            registry,
            preparation.frozen_run_spec_artifact_sha256,
        )
    )
    plan_record, plan_value, _ = _load_scientific_execution_json(
        registry,
        preparation.execution_plan_artifact_sha256,
        logical_type=SCIENTIFIC_EXECUTION_PLAN_LOGICAL_TYPE,
        creator_role=Role.PROTOCOL_DESIGNER,
    )
    input_binding_record, input_binding_value, _ = (
        _load_scientific_execution_json(
            registry,
            preparation.execution_input_binding_artifact_sha256,
            logical_type=SCIENTIFIC_EXECUTION_INPUT_BINDING_LOGICAL_TYPE,
            creator_role=Role.PROTOCOL_DESIGNER,
        )
    )
    if (
        plan_record.origin != _SCIENTIFIC_EXECUTION_PREPARATION_ORIGIN
        or plan_record.creation_command
        != _SCIENTIFIC_EXECUTION_PREPARATION_COMMAND
        or plan_record.parent_artifacts != (spec_record.sha256,)
        or input_binding_record.origin != _SCIENTIFIC_EXECUTION_PREPARATION_ORIGIN
        or input_binding_record.creation_command
        != _SCIENTIFIC_EXECUTION_PREPARATION_COMMAND
        or input_binding_record.parent_artifacts
        != (
            spec_record.sha256,
            plan_record.sha256,
            *(item.sha256 for item in input_records),
        )
    ):
        raise ExperimentError(
            "scientific execution plan or input-binding parents are substituted"
        )
    expected_plan_keys = {
        "schema_version",
        "ledger_run_id",
        "execution_run_id",
        "frozen_run_spec_artifact_sha256",
        "frozen_run_spec_sha256",
        "scientific_binding_sha256",
        "adaptive_execution_plan",
        "backend_profile",
        "authority_scope",
        "scientific_evidence",
    }
    if set(plan_value) != expected_plan_keys:
        raise ExperimentError("scientific execution plan schema is invalid")
    plan = AdaptiveExecutionPlan.from_mapping(plan_value["adaptive_execution_plan"])
    expected_plan_value = {
        "schema_version": SCIENTIFIC_EXECUTION_PLAN_SCHEMA,
        "ledger_run_id": expected_ledger_run_id,
        "execution_run_id": expected_execution_run_id,
        "frozen_run_spec_artifact_sha256": spec_record.sha256,
        "frozen_run_spec_sha256": spec.sha256,
        "scientific_binding_sha256": spec.scientific_binding_sha256,
        "adaptive_execution_plan": plan.to_dict(),
        "backend_profile": preparation.backend_profile.to_dict(),
        "authority_scope": "PROSPECTIVE_PROTOCOL_ONLY",
        "scientific_evidence": False,
    }
    expected_inputs = [
        {
            "kind": kind,
            "artifact_sha256": item.sha256,
            "artifact_record_hash": str(item.record_hash),
            "logical_type": item.logical_type,
            "creator_role": item.creator_role.value,
            "size": item.size,
        }
        for kind, item in zip(
            ("code", "data", "configuration", "evaluator"),
            input_records,
            strict=True,
        )
    ]
    expected_binding_value = {
        "schema_version": SCIENTIFIC_EXECUTION_INPUT_BINDING_SCHEMA,
        "ledger_run_id": expected_ledger_run_id,
        "execution_run_id": expected_execution_run_id,
        "frozen_run_spec_artifact_sha256": spec_record.sha256,
        "frozen_run_spec_sha256": spec.sha256,
        "execution_plan_artifact_sha256": plan_record.sha256,
        "execution_plan_sha256": plan.sha256,
        "argv": list(spec.argv),
        "working_directory": spec.working_directory,
        "seeds": list(spec.seeds),
        "inputs": expected_inputs,
        "authority_scope": "PROSPECTIVE_PROTOCOL_ONLY",
        "scientific_evidence": False,
    }
    _validate_adaptive_plan_binding(
        plan,
        spec.compute_profile,
        spec.resource_estimate,
        pending_tasks=len(spec.seeds),
        bytes_per_sample=spec.bytes_per_sample,
        worker_overhead_bytes=spec.worker_overhead_bytes,
    )
    if (
        dict(plan_value) != expected_plan_value
        or dict(input_binding_value) != expected_binding_value
        or preparation.frozen_run_spec_record_hash != spec_record.record_hash
        or preparation.frozen_run_spec_sha256 != spec.sha256
        or preparation.scientific_binding_sha256 != spec.scientific_binding_sha256
        or preparation.execution_plan_record_hash != plan_record.record_hash
        or preparation.execution_plan_sha256 != plan.sha256
        or preparation.execution_input_binding_record_hash
        != input_binding_record.record_hash
        or preparation.input_artifact_sha256s
        != tuple(item.sha256 for item in input_records)
        or preparation.input_artifact_record_hashes
        != tuple(str(item.record_hash) for item in input_records)
    ):
        raise ExperimentError(
            "scientific execution preparation differs from fresh input replay"
        )
    binding = _scientific_execution_preparation_binding(
        preparation_id=preparation.preparation_id,
        ledger_run_id=expected_ledger_run_id,
        spec_record=spec_record,
        spec=spec,
        plan_record=plan_record,
        plan=plan,
        input_binding_record=input_binding_record,
        input_records=input_records,
        backend_profile=preparation.backend_profile,
        challenge_nonce=preparation.challenge_nonce,
    )
    candidates: list[tuple[int, LedgerEvent]] = []
    for index, event in enumerate(events):
        candidate = thaw_json(event.metadata).get(
            "scientific_execution_preparation"
        )
        if (
            isinstance(candidate, Mapping)
            and candidate.get("execution_run_id") == expected_execution_run_id
        ):
            if dict(candidate) != binding:
                raise ExperimentError(
                    "competing scientific execution preparation is present"
                )
            candidates.append((index, event))
    if len(candidates) != 1:
        raise ExperimentError(
            "scientific execution requires one exact preparation event"
        )
    event_index, event = candidates[0]
    source_records = (
        spec_record,
        plan_record,
        input_binding_record,
        *input_records,
    )
    if (
        event.event_id != preparation.ledger_event_id
        or event.event_hash != preparation.ledger_event_hash
        or event_index != preparation.ledger_event_index
    ):
        raise ExperimentError("scientific execution preparation event identity changed")
    _validate_scientific_execution_preparation_event(
        event,
        event_index,
        events,
        binding=binding,
        source_records=source_records,
        spec=spec,
    )
    _require_scientific_execution_snapshot_unchanged(
        registry,
        ledger,
        expected_ledger_run_id,
        entry_registry,
        entry_ledger,
    )
    return preparation


@dataclass(frozen=True, slots=True)
class _ScientificExecutionCandidate:
    preparation_record: ArtifactRecord
    preparation: ScientificExecutionPreparation
    spec_record: ArtifactRecord
    spec: FrozenRunSpec
    manifest_record: ArtifactRecord
    manifest: OutputManifest
    output_records: tuple[ArtifactRecord, ...]
    environment_record: ArtifactRecord
    environment: Mapping[str, Any]
    isolation_record: ArtifactRecord
    isolation: Mapping[str, Any]
    activity_record: ArtifactRecord | None
    activity: ScientificExecutionActivity | None
    attestation_record: ArtifactRecord
    attestation: Mapping[str, Any]
    claim: Mapping[str, Any]


def derive_scientific_execution_outcome(
    spec: FrozenRunSpec,
    manifest: OutputManifest,
) -> ScientificExecutionOutcome:
    """Purely derive the backend execution outcome from the typed manifest.

    This function does not verify a backend signature and cannot issue an
    authority artifact.  It exists so the future closed verifier path cannot
    accept a signed, caller-selected outcome that contradicts the exact seed
    or required-ablation state.
    """

    if not isinstance(spec, FrozenRunSpec) or not isinstance(
        manifest, OutputManifest
    ):
        raise ExperimentError(
            "scientific execution outcome requires typed spec and manifest"
        )
    if (
        manifest.run_id != spec.run_id
        or manifest.spec_sha256 != spec.sha256
        or manifest.planned_seeds != spec.seeds
        or tuple(item.seed for item in manifest.seed_results) != spec.seeds
        or len({item.seed for item in manifest.seed_results})
        != len(manifest.seed_results)
        or tuple(item.ablation_id for item in manifest.ablations)
        != spec.required_ablations
        or len({item.ablation_id for item in manifest.ablations})
        != len(manifest.ablations)
    ):
        raise ExperimentError(
            "scientific execution outcome closure differs from the frozen plan"
        )
    # expected_outputs is the frozen minimum-required interface, not a closed
    # allow-list.  A manifest may additionally carry its declared raw paired
    # and ablation outputs; result promotion independently requires every
    # manifest descriptor to be reopened and consumed exactly once.
    if _missing_expected_output_types(spec, manifest):
        raise ExperimentError(
            "scientific execution omits a frozen expected output type"
        )
    seed_statuses = tuple(item.status for item in manifest.seed_results)
    ablation_statuses = tuple(item.status for item in manifest.ablations)
    if (
        SeedRunStatus.INVALID in seed_statuses
        or "INVALID" in ablation_statuses
    ):
        return ScientificExecutionOutcome.INVALID_OUTPUT
    if SeedRunStatus.FAILED in seed_statuses or "FAIL" in ablation_statuses:
        return ScientificExecutionOutcome.FAILED
    if any(
        status
        not in {
            SeedRunStatus.SUCCESS,
            SeedRunStatus.NEGATIVE,
            SeedRunStatus.NULL,
        }
        for status in seed_statuses
    ) or any(status != "PASS" for status in ablation_statuses):
        raise ExperimentError("scientific execution manifest has no closed outcome")
    return ScientificExecutionOutcome.COMPLETED


def validate_scientific_execution_attestation_claim(
    claim: Mapping[str, Any],
    expected_claim: Mapping[str, Any],
) -> str:
    """Purely validate exact claim binding; this does not verify a signature.

    Keeping this helper non-issuing lets tests cover canonical binding without
    introducing a callable verifier seam into production authority creation.
    """

    if not isinstance(claim, Mapping) or not isinstance(expected_claim, Mapping):
        raise ExperimentError("scientific execution claim must be a mapping")
    try:
        claim_bytes = canonical_json_bytes(claim)
        expected_bytes = canonical_json_bytes(expected_claim)
    except (TypeError, ValueError, ValidationError) as exc:
        raise ExperimentError("scientific execution claim is not canonical JSON") from exc
    if len(claim_bytes) > MAX_OUTPUT_MANIFEST_BYTES:
        raise ExperimentError("scientific execution claim exceeds its byte bound")
    if claim_bytes != expected_bytes:
        raise ExperimentError(
            "scientific execution claim differs from the exact execution closure"
        )
    return hashlib.sha256(claim_bytes).hexdigest()


def _scientific_execution_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ExperimentError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExperimentError(f"{label} is malformed") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ExperimentError(f"{label} must be UTC")
    return parsed


def _scientific_execution_expected_claim(
    candidate: _ScientificExecutionCandidate,
) -> dict[str, Any]:
    claim = candidate.claim
    expected_claim_keys = {
        "schema_version",
        "ledger_run_id",
        "execution_run_id",
        "backend_profile",
        "backend_job_id",
        "provider_invocation_id",
        "challenge_nonce",
        "preparation_artifact_sha256",
        "frozen_run_spec_artifact_sha256",
        "frozen_run_spec_sha256",
        "scientific_binding_sha256",
        "execution_plan_artifact_sha256",
        "execution_plan_sha256",
        "execution_input_binding_artifact_sha256",
        "input_artifact_sha256s",
        "input_artifact_record_hashes",
        "argv",
        "seeds",
        "output_manifest_artifact_sha256",
        "output_manifest_record_hash",
        "output_artifact_sha256s",
        "output_artifact_record_hashes",
        "environment_artifact_sha256",
        "environment_record_hash",
        "environment_fingerprint",
        "isolation_attestation_artifact_sha256",
        "isolation_attestation_record_hash",
        "isolation_policy_sha256",
        "network_used",
        "cache_used",
        "checkpoint_used",
        "resumed_from_checkpoint",
        "attested_started_at",
        "attested_completed_at",
        "outcome",
    }
    if candidate.activity is not None:
        expected_claim_keys.update(
            {
                "execution_activity_artifact_sha256",
                "execution_activity_record_hash",
                "execution_activity_capture_profile",
            }
        )
    if set(claim) != expected_claim_keys:
        raise ExperimentError("scientific backend execution claim schema is invalid")
    for name in ("backend_job_id", "provider_invocation_id"):
        validate_identifier(claim[name], name.replace("_", " "))
    started = _scientific_execution_timestamp(
        claim["attested_started_at"], "attested start"
    )
    completed = _scientific_execution_timestamp(
        claim["attested_completed_at"], "attested completion"
    )
    if started > completed:
        raise ExperimentError("scientific backend execution timestamps are reversed")
    try:
        outcome = ScientificExecutionOutcome(claim["outcome"])
    except (TypeError, ValueError) as exc:
        raise ExperimentError("scientific backend execution outcome is invalid") from exc
    derived_outcome = derive_scientific_execution_outcome(
        candidate.spec,
        candidate.manifest,
    )
    if outcome is not derived_outcome:
        raise ExperimentError(
            "scientific backend execution outcome contradicts the exact manifest"
        )
    if candidate.activity is not None:
        terminal = candidate.activity.terminal
        if terminal.occurred_at != claim["attested_completed_at"]:
            raise ExperimentError(
                "scientific activity terminal differs from attested completion"
            )
        if derived_outcome is ScientificExecutionOutcome.COMPLETED:
            expected_terminal = (
                ScientificExecutionTerminalKind.ALL_PLANNED_WORK_COMPLETED
            )
            if terminal.kind is not expected_terminal:
                raise ExperimentError(
                    "completed scientific execution lacks a completed activity terminal"
                )
        elif terminal.kind is ScientificExecutionTerminalKind.ALL_PLANNED_WORK_COMPLETED:
            raise ExperimentError(
                "failed scientific execution cannot claim completed planned activity"
            )
    preparation_time = _scientific_execution_timestamp(
        candidate.preparation_record.created_at,
        "scientific execution preparation artifact time",
    )
    if started < preparation_time:
        raise ExperimentError(
            "scientific backend execution predates its prospective preparation"
        )
    isolation = candidate.isolation
    for name in (
        "network_used",
        "cache_used",
        "checkpoint_used",
        "resumed_from_checkpoint",
    ):
        if not isinstance(isolation[name], bool):
            raise ExperimentError(f"scientific execution {name} must be boolean")
    result = {
        "schema_version": (
            SCIENTIFIC_BACKEND_EXECUTION_CLAIM_SCHEMA_V2
            if candidate.activity is not None
            else SCIENTIFIC_BACKEND_EXECUTION_CLAIM_SCHEMA
        ),
        "ledger_run_id": candidate.preparation.ledger_run_id,
        "execution_run_id": candidate.preparation.execution_run_id,
        "backend_profile": candidate.preparation.backend_profile.to_dict(),
        "backend_job_id": claim["backend_job_id"],
        "provider_invocation_id": claim["provider_invocation_id"],
        "challenge_nonce": candidate.preparation.challenge_nonce,
        "preparation_artifact_sha256": candidate.preparation_record.sha256,
        "frozen_run_spec_artifact_sha256": candidate.spec_record.sha256,
        "frozen_run_spec_sha256": candidate.spec.sha256,
        "scientific_binding_sha256": candidate.spec.scientific_binding_sha256,
        "execution_plan_artifact_sha256": (
            candidate.preparation.execution_plan_artifact_sha256
        ),
        "execution_plan_sha256": candidate.preparation.execution_plan_sha256,
        "execution_input_binding_artifact_sha256": (
            candidate.preparation.execution_input_binding_artifact_sha256
        ),
        "input_artifact_sha256s": list(
            candidate.preparation.input_artifact_sha256s
        ),
        "input_artifact_record_hashes": list(
            candidate.preparation.input_artifact_record_hashes
        ),
        "argv": list(candidate.spec.argv),
        "seeds": list(candidate.spec.seeds),
        "output_manifest_artifact_sha256": candidate.manifest_record.sha256,
        "output_manifest_record_hash": str(candidate.manifest_record.record_hash),
        "output_artifact_sha256s": [
            record.sha256 for record in candidate.output_records
        ],
        "output_artifact_record_hashes": [
            str(record.record_hash) for record in candidate.output_records
        ],
        "environment_artifact_sha256": candidate.environment_record.sha256,
        "environment_record_hash": str(candidate.environment_record.record_hash),
        "environment_fingerprint": candidate.environment["environment_fingerprint"],
        "isolation_attestation_artifact_sha256": candidate.isolation_record.sha256,
        "isolation_attestation_record_hash": str(candidate.isolation_record.record_hash),
        "isolation_policy_sha256": candidate.isolation["isolation_policy_sha256"],
        "network_used": isolation["network_used"],
        "cache_used": isolation["cache_used"],
        "checkpoint_used": isolation["checkpoint_used"],
        "resumed_from_checkpoint": isolation["resumed_from_checkpoint"],
        "attested_started_at": claim["attested_started_at"],
        "attested_completed_at": claim["attested_completed_at"],
        "outcome": derived_outcome.value,
    }
    if candidate.activity is not None:
        assert candidate.activity_record is not None
        result.update(
            {
                "execution_activity_artifact_sha256": (
                    candidate.activity_record.sha256
                ),
                "execution_activity_record_hash": str(
                    candidate.activity_record.record_hash
                ),
                "execution_activity_capture_profile": (
                    candidate.activity.capture_profile
                ),
            }
        )
    return result


def _require_numeric_ablation_selected_output_capacity(
    outputs: tuple[tuple[OutputArtifact, ArtifactRecord], ...],
) -> None:
    """Bound the new profile's accepted selected outputs, not allocations.

    This is a pure metadata/descriptor check for ALL selected logical types.
    Outer source snapshots and recursive registry.verify may already read
    bodies under the existing registry limits. Neither this preflight nor its
    immediate per-read repetition is an atomic first-allocation/race guard.
    The ordinary content, provenance and metadata checks remain necessary.
    """

    from .generic_ml_ablation_output import MAX_GENERIC_ML_ABLATION_OUTPUT_BYTES

    if type(outputs) is not tuple or len(outputs) > MAX_OUTPUT_ARTIFACTS:
        raise ExperimentError("numeric ablation selected output collection exceeds its bound")
    total = 0
    for item in outputs:
        if type(item) is not tuple or len(item) != 2:
            raise ExperimentError("numeric ablation selected output requires a metadata/descriptor pair")
        descriptor, record = item
        if type(descriptor) is not OutputArtifact or type(record) is not ArtifactRecord:
            raise ExperimentError("numeric ablation selected output requires exact metadata/descriptor types")
        if (
            type(descriptor.size) is not int
            or type(record.size) is not int
            or not 0 < descriptor.size <= MAX_GENERIC_ML_ABLATION_OUTPUT_BYTES
            or not 0 < record.size <= MAX_GENERIC_ML_ABLATION_OUTPUT_BYTES
            or descriptor.size != record.size
        ):
            raise ExperimentError("numeric ablation selected output size is invalid or differs from metadata")
        total += record.size
        if total > MAX_RETURNED_ARTIFACT_TOTAL_BYTES:
            raise ExperimentError("numeric ablation selected outputs exceed the existing total byte bound")


def _load_scientific_execution_candidate(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    preparation_artifact_sha256: str,
    output_manifest_artifact_sha256: str,
    environment_artifact_sha256: str,
    isolation_attestation_artifact_sha256: str,
    backend_attestation_artifact_sha256: str,
    execution_activity_artifact_sha256: str | None,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
) -> _ScientificExecutionCandidate:
    preparation = require_scientific_execution_preparation(
        registry,
        ledger,
        preparation_artifact_sha256=preparation_artifact_sha256,
        expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_execution_run_id,
    )
    preparation_record = registry.get_metadata(preparation_artifact_sha256)
    spec_record, spec, _input_records = _require_scientific_execution_spec_and_inputs(
        registry,
        preparation.frozen_run_spec_artifact_sha256,
    )
    manifest_record, manifest_value, _ = _load_scientific_execution_json(
        registry,
        output_manifest_artifact_sha256,
        logical_type="experiment_output_manifest",
        creator_role=Role.EXPERIMENT_RUNNER,
    )
    manifest = OutputManifest.from_mapping(manifest_value)
    if (
        manifest_record.parent_artifacts != (spec_record.sha256,)
        or manifest.run_id != spec.run_id
        or manifest.spec_sha256 != spec.sha256
        or manifest.code_sha256 != spec.code_sha256
        or manifest.data_sha256 != spec.data_sha256
        or manifest.configuration_sha256 != spec.configuration_sha256
        or manifest.evaluator_sha256 != spec.evaluator_sha256
        or manifest.planned_seeds != spec.seeds
        or tuple(item.seed for item in manifest.seed_results) != spec.seeds
        or len({item.seed for item in manifest.seed_results})
        != len(manifest.seed_results)
    ):
        raise ExperimentError(
            "scientific execution manifest differs from the frozen run spec"
        )
    from .scientific_numeric_ablation import SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY

    numeric_ablation_outputs = (
        SCIENTIFIC_NUMERIC_ABLATION_POLICY_METADATA_KEY in thaw_json(spec.metadata)
    )
    if numeric_ablation_outputs:
        # Bound metadata traversal before visiting any selected output. These
        # are upper bounds, not completeness/PASS gates: failed and timed-out
        # attempts may retain empty or partial observations. Exact 4S+A and
        # ablation identity closure belong to later numeric/admissibility owners.
        if (
            len(manifest.artifacts) > 4 * len(spec.seeds) + len(spec.required_ablations)
            or len(manifest.ablations) > len(spec.required_ablations)
        ):
            raise ExperimentError(
                "numeric ablation manifest exceeds prospective output or ablation count bounds"
            )
        try:
            selected_output_metadata = tuple(
                (descriptor, registry.get_metadata(descriptor.sha256))
                for descriptor in manifest.artifacts
            )
        except (ArtifactError, ValidationError) as exc:
            raise ExperimentError(
                "numeric ablation selected output capacity metadata cannot be reopened"
            ) from exc
        _require_numeric_ablation_selected_output_capacity(selected_output_metadata)
    output_records: list[ArtifactRecord] = []
    for descriptor in manifest.artifacts:
        try:
            registry.verify(descriptor.sha256, raise_on_error=True)
            output_record = registry.get_metadata(descriptor.sha256)
            if numeric_ablation_outputs:
                _require_numeric_ablation_selected_output_capacity(((descriptor, output_record),))
            output_bytes = registry.get_bytes(descriptor.sha256)
        except (ArtifactError, ValidationError) as exc:
            raise ExperimentError(
                "scientific execution output cannot be reopened"
            ) from exc
        if (
            output_record.logical_type
            != f"experiment_output.{descriptor.logical_type}"
            or output_record.creator_role is not Role.EXPERIMENT_RUNNER
            or output_record.size != descriptor.size
            or output_record.size != len(output_bytes)
            or output_record.validation_result != "PASS"
            or not output_record.frozen
            or output_record.parent_artifacts
            != (manifest_record.sha256, spec_record.sha256)
        ):
            raise ExperimentError(
                "scientific execution output metadata or parents are substituted"
            )
        output_records.append(output_record)
    if len({record.sha256 for record in output_records}) != len(output_records):
        raise ExperimentError("scientific execution manifest duplicates output bytes")
    output_hashes = {record.sha256 for record in output_records}
    if any(
        result.artifact_sha256 is not None
        and result.artifact_sha256 not in output_hashes
        for result in manifest.seed_results
    ) or any(
        result.artifact_sha256 not in output_hashes for result in manifest.ablations
    ):
        raise ExperimentError("scientific execution result references undeclared bytes")
    environment_record, environment, _ = _load_scientific_execution_json(
        registry,
        environment_artifact_sha256,
        logical_type=SCIENTIFIC_EXECUTION_ENVIRONMENT_LOGICAL_TYPE,
        creator_role=Role.EXPERIMENT_RUNNER,
    )
    isolation_record, isolation, _ = _load_scientific_execution_json(
        registry,
        isolation_attestation_artifact_sha256,
        logical_type=SCIENTIFIC_EXECUTION_ISOLATION_LOGICAL_TYPE,
        creator_role=Role.EXPERIMENT_RUNNER,
    )
    activity_record: ArtifactRecord | None = None
    activity: ScientificExecutionActivity | None = None
    if execution_activity_artifact_sha256 is not None:
        if (
            preparation.backend_profile.attestation_schema
            != SCIENTIFIC_COMPLETE_ACTIVITY_ATTESTATION_SCHEMA
        ):
            raise ExperimentError(
                "scientific activity requires the exhaustive-capture attestation profile"
            )
        activity = require_scientific_execution_activity(
            registry,
            activity_artifact_sha256=execution_activity_artifact_sha256,
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
            expected_preparation_artifact_sha256=preparation_record.sha256,
            expected_frozen_run_spec_artifact_sha256=spec_record.sha256,
            expected_output_manifest_artifact_sha256=manifest_record.sha256,
        )
        activity_record = registry.get_metadata(
            execution_activity_artifact_sha256
        )
    elif (
        preparation.backend_profile.attestation_schema
        == SCIENTIFIC_COMPLETE_ACTIVITY_ATTESTATION_SCHEMA
    ):
        raise ExperimentError(
            "exhaustive-capture backend profile requires a scientific activity artifact"
        )
    attestation_record, attestation, _ = _load_scientific_execution_json(
        registry,
        backend_attestation_artifact_sha256,
        logical_type=SCIENTIFIC_BACKEND_ATTESTATION_LOGICAL_TYPE,
        creator_role=Role.EXPERIMENT_RUNNER,
    )
    environment_keys = {
        "schema_version",
        "ledger_run_id",
        "execution_run_id",
        "backend_profile",
        "environment_fingerprint",
        "host_instance_id",
        "boot_session_id",
        "hardware_fingerprint",
        "writable_storage_id",
        "claims",
    }
    isolation_keys = {
        "schema_version",
        "ledger_run_id",
        "execution_run_id",
        "backend_profile",
        "environment_artifact_sha256",
        "isolation_policy_sha256",
        "network_used",
        "network_isolation_attested",
        "shared_writable_state_ids",
        "cache_used",
        "checkpoint_used",
        "resumed_from_checkpoint",
        "claims",
    }
    attestation_keys = {"schema_version", "backend_profile", "claim", "signature"}
    expected_attestation_schema = (
        SCIENTIFIC_BACKEND_ATTESTATION_ENVELOPE_SCHEMA_V2
        if activity_record is not None
        else SCIENTIFIC_BACKEND_ATTESTATION_ENVELOPE_SCHEMA
    )
    expected_attestation_parents = (
        preparation_record.sha256,
        manifest_record.sha256,
        environment_record.sha256,
        isolation_record.sha256,
        *((activity_record.sha256,) if activity_record is not None else ()),
    )
    if (
        set(environment) != environment_keys
        or set(isolation) != isolation_keys
        or set(attestation) != attestation_keys
        or environment["schema_version"]
        != SCIENTIFIC_EXECUTION_ENVIRONMENT_SCHEMA
        or isolation["schema_version"] != SCIENTIFIC_EXECUTION_ISOLATION_SCHEMA
        or attestation["schema_version"] != expected_attestation_schema
        or environment["ledger_run_id"] != expected_ledger_run_id
        or isolation["ledger_run_id"] != expected_ledger_run_id
        or environment["execution_run_id"] != expected_execution_run_id
        or isolation["execution_run_id"] != expected_execution_run_id
        or environment["backend_profile"] != preparation.backend_profile.to_dict()
        or isolation["backend_profile"] != preparation.backend_profile.to_dict()
        or attestation["backend_profile"] != preparation.backend_profile.to_dict()
        or environment_record.parent_artifacts
        != (preparation_record.sha256,)
        or isolation_record.parent_artifacts
        != (preparation_record.sha256, environment_record.sha256)
        or attestation_record.parent_artifacts != expected_attestation_parents
        or isolation["environment_artifact_sha256"] != environment_record.sha256
        or isolation["network_used"] is not False
        or isolation["network_isolation_attested"] is not True
        or isolation["shared_writable_state_ids"] != []
        or not isinstance(environment["claims"], Mapping)
        or not isinstance(isolation["claims"], Mapping)
        or not isinstance(attestation["claim"], Mapping)
        or not isinstance(attestation["signature"], str)
        or not attestation["signature"]
    ):
        raise ExperimentError(
            "scientific execution environment, isolation, or attestation envelope is invalid"
        )
    for name, value in (
        ("environment fingerprint", environment["environment_fingerprint"]),
        ("hardware fingerprint", environment["hardware_fingerprint"]),
        ("isolation policy", isolation["isolation_policy_sha256"]),
    ):
        validate_sha256(value, name)
    for name in ("host_instance_id", "boot_session_id", "writable_storage_id"):
        validate_identifier(environment[name], name.replace("_", " "))
    preparation_time = _scientific_execution_timestamp(
        ledger.events()[preparation.ledger_event_index].timestamp,
        "scientific execution preparation event time",
    )
    manifest_time = _scientific_execution_timestamp(
        manifest_record.created_at,
        "scientific execution manifest creation time",
    )
    if manifest_time < preparation_time:
        raise ExperimentError(
            "scientific execution manifest predates its prospective preparation"
        )
    if activity_record is not None:
        activity_time = _scientific_execution_timestamp(
            activity_record.created_at,
            "scientific execution activity creation time",
        )
        attestation_time = _scientific_execution_timestamp(
            attestation_record.created_at,
            "scientific execution attestation creation time",
        )
        if attestation_time < activity_time:
            raise ExperimentError(
                "scientific execution attestation predates its activity closure"
            )
    candidate = _ScientificExecutionCandidate(
        preparation_record=preparation_record,
        preparation=preparation,
        spec_record=spec_record,
        spec=spec,
        manifest_record=manifest_record,
        manifest=manifest,
        output_records=tuple(output_records),
        environment_record=environment_record,
        environment=environment,
        isolation_record=isolation_record,
        isolation=isolation,
        activity_record=activity_record,
        activity=activity,
        attestation_record=attestation_record,
        attestation=attestation,
        claim=attestation["claim"],
    )
    expected_claim = _scientific_execution_expected_claim(candidate)
    validate_scientific_execution_attestation_claim(
        candidate.claim,
        expected_claim,
    )
    return candidate


class _ScientificBackendAttestationVerifier(Protocol):
    """Private source-installed verifier contract; never caller supplied."""

    def verify(
        self,
        *,
        profile: ScientificBackendAttestationProfile,
        canonical_envelope: bytes,
        canonical_claim: bytes,
        claim_sha256: str,
    ) -> bool: ...


def _verify_scientific_execution_candidate(
    registry: ArtifactRegistry,
    candidate: _ScientificExecutionCandidate,
    verifier: _ScientificBackendAttestationVerifier,
) -> str:
    expected_claim = _scientific_execution_expected_claim(candidate)
    claim_sha256 = validate_scientific_execution_attestation_claim(
        candidate.claim,
        expected_claim,
    )
    envelope_bytes = registry.get_bytes(candidate.attestation_record.sha256)
    claim_bytes = canonical_json_bytes(candidate.claim)
    try:
        verified = verifier.verify(
            profile=candidate.preparation.backend_profile,
            canonical_envelope=envelope_bytes,
            canonical_claim=claim_bytes,
            claim_sha256=claim_sha256,
        )
    except Exception as exc:
        raise ExperimentError(
            "scientific backend attestation verifier failed closed"
        ) from exc
    if verified is not True:
        raise ExperimentError("scientific backend attestation was not verified")
    return claim_sha256


def _scientific_execution_authority_source_records(
    registry: ArtifactRegistry,
    candidate: _ScientificExecutionCandidate,
) -> tuple[ArtifactRecord, ...]:
    records = (
        candidate.preparation_record,
        candidate.spec_record,
        registry.get_metadata(
            candidate.preparation.execution_plan_artifact_sha256
        ),
        registry.get_metadata(
            candidate.preparation.execution_input_binding_artifact_sha256
        ),
        candidate.manifest_record,
        *candidate.output_records,
        candidate.environment_record,
        candidate.isolation_record,
    )
    if candidate.activity_record is not None:
        records += (candidate.activity_record,)
    records += (candidate.attestation_record,)
    if (
        len(records) > MAX_ARTIFACT_PARENTS
        or len({item.sha256 for item in records}) != len(records)
        or any(item.record_hash is None for item in records)
    ):
        raise ExperimentError(
            "scientific execution authority source closure is ambiguous or too large"
        )
    return records


def _scientific_execution_authority_identity(
    candidate: _ScientificExecutionCandidate,
    claim_sha256: str,
) -> str:
    digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "preparation_artifact_sha256": candidate.preparation_record.sha256,
                "backend_attestation_artifact_sha256": (
                    candidate.attestation_record.sha256
                ),
                "backend_claim_sha256": claim_sha256,
                "execution_run_id": candidate.preparation.execution_run_id,
            }
        )
    ).hexdigest()
    return f"scientific-execution-{digest[:24]}"


def _scientific_execution_authority_binding(
    candidate: _ScientificExecutionCandidate,
    *,
    authority_id: str,
    claim_sha256: str,
    source_records: tuple[ArtifactRecord, ...],
) -> dict[str, Any]:
    outcome = derive_scientific_execution_outcome(candidate.spec, candidate.manifest)
    return {
        "schema_version": (
            SCIENTIFIC_EXECUTION_AUTHORITY_EVENT_SCHEMA_V2
            if candidate.activity_record is not None
            else SCIENTIFIC_EXECUTION_AUTHORITY_EVENT_SCHEMA
        ),
        "kind": "SCIENTIFIC_EXECUTION_ATTESTED",
        "authority_id": authority_id,
        "ledger_run_id": candidate.preparation.ledger_run_id,
        "execution_run_id": candidate.preparation.execution_run_id,
        "preparation_artifact_sha256": candidate.preparation_record.sha256,
        "challenge_nonce": candidate.preparation.challenge_nonce,
        "backend_profile": candidate.preparation.backend_profile.to_dict(),
        "backend_claim_sha256": claim_sha256,
        "outcome": outcome.value,
        "artifact_sha256s": [item.sha256 for item in source_records],
        "artifact_record_hashes": [
            str(item.record_hash) for item in source_records
        ],
        "authority_scope": "SCIENTIFIC_EXECUTION_ATTESTATION",
    }


def _scientific_execution_authority_slot_matches(
    candidate: object,
    *,
    ledger_run_id: str,
    execution_run_id: str,
    preparation_artifact_sha256: str,
    challenge_nonce: str,
) -> bool:
    """Match every identity that makes one preparation a one-use authority slot."""

    if not isinstance(candidate, Mapping):
        return False
    return (
        candidate.get("preparation_artifact_sha256")
        == preparation_artifact_sha256
        or candidate.get("challenge_nonce") == challenge_nonce
        or (
            candidate.get("ledger_run_id") == ledger_run_id
            and candidate.get("execution_run_id") == execution_run_id
        )
    )


def _validate_scientific_execution_authority_event(
    event: LedgerEvent,
    event_index: int,
    events: tuple[LedgerEvent, ...],
    *,
    candidate: _ScientificExecutionCandidate,
    binding: Mapping[str, Any],
    source_records: tuple[ArtifactRecord, ...],
) -> None:
    if (
        event.event_hash is None
        or event.actor_role is not Role.CLAIM_VERIFIER
        or event.event_type != "CHECKPOINT"
        or event.state_before != event.state_after
        or event.artifact_hashes
        != tuple(item.sha256 for item in source_records)
        or event.code_version != f"sha256:{candidate.spec.code_sha256}"
        or event.configuration_hash != candidate.spec.configuration_sha256
        or event.dataset_identifiers != (candidate.spec.data_sha256,)
        or event.random_seeds != candidate.spec.seeds
        or event.evaluator_outputs
        != tuple(item.sha256 for item in candidate.output_records)
        or event.reason
        != (
            "verified one exact independently attested scientific execution "
            "against its prospective protocol and complete output closure"
        )
        or thaw_json(event.metadata)
        != {"scientific_execution_authority": dict(binding)}
        or any(
            item.event_type == "CORRECTION"
            and item.supersedes_event_id == event.event_id
            for item in events[event_index + 1 :]
        )
    ):
        raise ExperimentError(
            "scientific execution authority event is stale or substituted"
        )


def _scientific_execution_authority_from_event(
    candidate: _ScientificExecutionCandidate,
    *,
    authority_id: str,
    claim_sha256: str,
    event: LedgerEvent,
    event_index: int,
) -> ScientificExecutionAuthority:
    if event.event_hash is None:
        raise ExperimentError("scientific execution authority event hash is absent")
    claim = candidate.claim
    outcome = derive_scientific_execution_outcome(candidate.spec, candidate.manifest)
    return ScientificExecutionAuthority(
        authority_id=authority_id,
        ledger_run_id=candidate.preparation.ledger_run_id,
        execution_run_id=candidate.preparation.execution_run_id,
        ledger_path=candidate.preparation.ledger_path,
        preparation_artifact_sha256=candidate.preparation_record.sha256,
        preparation_record_hash=str(candidate.preparation_record.record_hash),
        frozen_run_spec_artifact_sha256=candidate.spec_record.sha256,
        frozen_run_spec_sha256=candidate.spec.sha256,
        scientific_binding_sha256=candidate.spec.scientific_binding_sha256,
        execution_plan_artifact_sha256=(
            candidate.preparation.execution_plan_artifact_sha256
        ),
        execution_input_binding_artifact_sha256=(
            candidate.preparation.execution_input_binding_artifact_sha256
        ),
        output_manifest_artifact_sha256=candidate.manifest_record.sha256,
        output_manifest_record_hash=str(candidate.manifest_record.record_hash),
        environment_artifact_sha256=candidate.environment_record.sha256,
        environment_record_hash=str(candidate.environment_record.record_hash),
        isolation_attestation_artifact_sha256=candidate.isolation_record.sha256,
        isolation_attestation_record_hash=str(candidate.isolation_record.record_hash),
        backend_attestation_artifact_sha256=candidate.attestation_record.sha256,
        backend_attestation_record_hash=str(candidate.attestation_record.record_hash),
        backend_profile=candidate.preparation.backend_profile,
        backend_job_id=str(claim["backend_job_id"]),
        provider_invocation_id=str(claim["provider_invocation_id"]),
        challenge_nonce=candidate.preparation.challenge_nonce,
        backend_claim_sha256=claim_sha256,
        output_artifact_sha256s=tuple(
            item.sha256 for item in candidate.output_records
        ),
        output_artifact_record_hashes=tuple(
            str(item.record_hash) for item in candidate.output_records
        ),
        environment_fingerprint=str(
            candidate.environment["environment_fingerprint"]
        ),
        isolation_policy_sha256=str(
            candidate.isolation["isolation_policy_sha256"]
        ),
        attested_started_at=str(claim["attested_started_at"]),
        attested_completed_at=str(claim["attested_completed_at"]),
        outcome=outcome,
        network_used=bool(candidate.isolation["network_used"]),
        cache_used=bool(candidate.isolation["cache_used"]),
        checkpoint_used=bool(candidate.isolation["checkpoint_used"]),
        resumed_from_checkpoint=bool(
            candidate.isolation["resumed_from_checkpoint"]
        ),
        ledger_event_id=event.event_id,
        ledger_event_hash=event.event_hash,
        ledger_event_index=event_index,
        ledger_prefix_head_hash=event.event_hash,
        execution_activity_artifact_sha256=(
            None
            if candidate.activity_record is None
            else candidate.activity_record.sha256
        ),
        execution_activity_record_hash=(
            None
            if candidate.activity_record is None
            else str(candidate.activity_record.record_hash)
        ),
    )


def _scientific_execution_authority_publication_binding(
    record: ArtifactRecord,
    authority: ScientificExecutionAuthority,
) -> dict[str, Any]:
    if record.record_hash is None:
        raise ExperimentError(
            "scientific execution authority publication lacks a record hash"
        )
    return {
        "schema_version": SCIENTIFIC_EXECUTION_AUTHORITY_PUBLICATION_EVENT_SCHEMA,
        "kind": "SCIENTIFIC_EXECUTION_AUTHORITY_PUBLISHED",
        "authority_id": authority.authority_id,
        "ledger_run_id": authority.ledger_run_id,
        "execution_run_id": authority.execution_run_id,
        "preparation_artifact_sha256": authority.preparation_artifact_sha256,
        "challenge_nonce": authority.challenge_nonce,
        "authority_artifact_sha256": record.sha256,
        "authority_artifact_record_hash": str(record.record_hash),
        "verification_event_id": authority.ledger_event_id,
        "verification_event_hash": authority.ledger_event_hash,
        "verification_event_index": authority.ledger_event_index,
        "authority_scope": authority.authority_scope,
    }


def _validate_scientific_execution_authority_publication_event(
    event: LedgerEvent,
    event_index: int,
    events: tuple[LedgerEvent, ...],
    *,
    record: ArtifactRecord,
    authority: ScientificExecutionAuthority,
    candidate: _ScientificExecutionCandidate,
) -> None:
    binding = _scientific_execution_authority_publication_binding(
        record,
        authority,
    )
    if (
        event.event_hash is None
        or event_index <= authority.ledger_event_index
        or event.actor_role is not Role.CLAIM_VERIFIER
        or event.event_type != "CHECKPOINT"
        or event.state_before != event.state_after
        or event.artifact_hashes != (record.sha256,)
        or event.code_version != f"sha256:{candidate.spec.code_sha256}"
        or event.configuration_hash != candidate.spec.configuration_sha256
        or event.dataset_identifiers != (candidate.spec.data_sha256,)
        or event.random_seeds != candidate.spec.seeds
        or event.evaluator_outputs
        or event.reason
        != "published the exact source-owned scientific execution authority"
        or thaw_json(event.metadata)
        != {"scientific_execution_authority_publication": binding}
        or any(
            item.event_type == "CORRECTION"
            and item.supersedes_event_id == event.event_id
            for item in events[event_index + 1 :]
        )
    ):
        raise ExperimentError(
            "scientific execution authority publication is stale or substituted"
        )


def _build_scientific_execution_authority_api():
    """Build the only production issuer around an immutable empty verifier map."""

    verifier_map: Mapping[
        tuple[str, str, str, str],
        _ScientificBackendAttestationVerifier,
    ] = MappingProxyType({})
    categorically_unsupported = frozenset(
        {"local-mac", "fake-gpu-cloud", "scheduled-gpu-cloud"}
    )
    load_candidate = _load_scientific_execution_candidate
    load_json = _load_scientific_execution_json
    verify_candidate = _verify_scientific_execution_candidate
    authority_source_records = _scientific_execution_authority_source_records
    authority_identity = _scientific_execution_authority_identity
    authority_binding = _scientific_execution_authority_binding
    slot_matches = _scientific_execution_authority_slot_matches
    validate_authority_event = _validate_scientific_execution_authority_event
    authority_from_event = _scientific_execution_authority_from_event
    authority_type = ScientificExecutionAuthority
    resolution_type = ScientificExecutionAuthorityResolution
    status_type = ScientificExecutionVerificationStatus
    unavailable_error = ScientificExecutionAuthorityUnavailable

    def authority_records_for_slot(
        registry: ArtifactRegistry,
        candidate: _ScientificExecutionCandidate,
    ) -> tuple[ArtifactRecord, ...]:
        records: list[ArtifactRecord] = []
        for item in registry.list_records():
            if item.logical_type != SCIENTIFIC_EXECUTION_AUTHORITY_LOGICAL_TYPE:
                continue
            if candidate.preparation_record.sha256 in item.parent_artifacts:
                records.append(item)
                continue
            try:
                value = safe_json_loads(registry.get_bytes(item.sha256))
            except (ArtifactError, ValidationError):
                continue
            if slot_matches(
                value,
                ledger_run_id=candidate.preparation.ledger_run_id,
                execution_run_id=candidate.preparation.execution_run_id,
                preparation_artifact_sha256=candidate.preparation_record.sha256,
                challenge_nonce=candidate.preparation.challenge_nonce,
            ):
                records.append(item)
        return tuple(records)

    def authority_events_for_slot(
        events: tuple[LedgerEvent, ...],
        candidate: _ScientificExecutionCandidate,
    ) -> tuple[tuple[int, LedgerEvent, Mapping[str, Any]], ...]:
        matches: list[tuple[int, LedgerEvent, Mapping[str, Any]]] = []
        for index, event in enumerate(events):
            metadata = thaw_json(event.metadata)
            admitted = metadata.get("scientific_execution_authority")
            if slot_matches(
                admitted,
                ledger_run_id=candidate.preparation.ledger_run_id,
                execution_run_id=candidate.preparation.execution_run_id,
                preparation_artifact_sha256=candidate.preparation_record.sha256,
                challenge_nonce=candidate.preparation.challenge_nonce,
            ):
                matches.append((index, event, admitted))
        return tuple(matches)

    def authority_publications_for_slot(
        events: tuple[LedgerEvent, ...],
        candidate: _ScientificExecutionCandidate,
    ) -> tuple[tuple[int, LedgerEvent, Mapping[str, Any]], ...]:
        matches: list[tuple[int, LedgerEvent, Mapping[str, Any]]] = []
        for index, event in enumerate(events):
            metadata = thaw_json(event.metadata)
            published = metadata.get(
                "scientific_execution_authority_publication"
            )
            if slot_matches(
                published,
                ledger_run_id=candidate.preparation.ledger_run_id,
                execution_run_id=candidate.preparation.execution_run_id,
                preparation_artifact_sha256=(
                    candidate.preparation_record.sha256
                ),
                challenge_nonce=candidate.preparation.challenge_nonce,
            ):
                matches.append((index, event, published))
        return tuple(matches)

    def resolve_scientific_execution_authority(
        registry: ArtifactRegistry,
        ledger: EventLedger,
        *,
        preparation_artifact_sha256: str,
        output_manifest_artifact_sha256: str,
        environment_artifact_sha256: str,
        isolation_attestation_artifact_sha256: str,
        backend_attestation_artifact_sha256: str,
        execution_activity_artifact_sha256: str | None = None,
        expected_ledger_run_id: str,
        expected_execution_run_id: str,
    ) -> ScientificExecutionAuthorityResolution:
        entry_registry, entry_ledger = _locked_scientific_execution_snapshot(
            registry,
            ledger,
            expected_ledger_run_id,
        )
        validate_sha256(
            preparation_artifact_sha256,
            "scientific execution preparation SHA-256",
        )
        validate_identifier(expected_ledger_run_id, "expected ledger run ID")
        validate_identifier(expected_execution_run_id, "expected execution run ID")
        candidate = load_candidate(
            registry,
            ledger,
            preparation_artifact_sha256=preparation_artifact_sha256,
            output_manifest_artifact_sha256=output_manifest_artifact_sha256,
            environment_artifact_sha256=environment_artifact_sha256,
            isolation_attestation_artifact_sha256=(
                isolation_attestation_artifact_sha256
            ),
            backend_attestation_artifact_sha256=(
                backend_attestation_artifact_sha256
            ),
            execution_activity_artifact_sha256=(
                execution_activity_artifact_sha256
            ),
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
        )
        profile = candidate.preparation.backend_profile
        if profile.backend_id in categorically_unsupported:
            resolution = resolution_type(
                status=status_type.UNSUPPORTED,
                reason_code="BACKEND_CATEGORICALLY_NON_SCIENTIFIC",
                reason=(
                    "The selected local, fake, scheduled, or injected backend has "
                    "no independent scientific execution authority."
                ),
                preparation_artifact_sha256=preparation_artifact_sha256,
            )
            _require_scientific_execution_snapshot_unchanged(
                registry,
                ledger,
                expected_ledger_run_id,
                entry_registry,
                entry_ledger,
            )
            return resolution
        verifier = verifier_map.get(profile.key)
        if verifier is None:
            resolution = resolution_type(
                status=status_type.BLOCKED_EXTERNAL,
                reason_code="BACKEND_ATTESTATION_VERIFIER_UNAVAILABLE",
                reason=(
                    "No independently provisioned production trust root and "
                    "source-owned backend attestation verifier is available."
                ),
                preparation_artifact_sha256=preparation_artifact_sha256,
            )
            _require_scientific_execution_snapshot_unchanged(
                registry,
                ledger,
                expected_ledger_run_id,
                entry_registry,
                entry_ledger,
            )
            return resolution
        verify_candidate(registry, candidate, verifier)
        matches = authority_records_for_slot(registry, candidate)
        if len(matches) > 1:
            raise ExperimentError("scientific execution authority slot is ambiguous")
        if not matches:
            admitted = authority_events_for_slot(entry_ledger.events, candidate)
            publications = authority_publications_for_slot(
                entry_ledger.events,
                candidate,
            )
            if admitted or publications:
                raise ExperimentError(
                    "scientific execution authority admission is incomplete and "
                    "requires source-owner recovery"
                )
            resolution = resolution_type(
                status=status_type.BLOCKED_EXTERNAL,
                reason_code="VERIFIED_ATTESTATION_NOT_REGISTERED",
                reason=(
                    "The closed backend verifier accepted the exact attestation, "
                    "but no source-owned authority artifact has been registered."
                ),
                preparation_artifact_sha256=preparation_artifact_sha256,
            )
            _require_scientific_execution_snapshot_unchanged(
                registry,
                ledger,
                expected_ledger_run_id,
                entry_registry,
                entry_ledger,
            )
            return resolution
        authority = require_scientific_execution_authority(
            registry,
            ledger,
            authority_artifact_sha256=matches[0].sha256,
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
        )
        resolution = resolution_type(
            status=status_type.VERIFIED,
            reason_code="SCIENTIFIC_EXECUTION_AUTHORITY_VERIFIED",
            reason=(
                "The exact execution closure and backend attestation passed "
                "fresh source-owned verification."
            ),
            preparation_artifact_sha256=preparation_artifact_sha256,
            authority_artifact_sha256=matches[0].sha256,
            authority=authority,
        )
        _require_scientific_execution_snapshot_unchanged(
            registry,
            ledger,
            expected_ledger_run_id,
            entry_registry,
            entry_ledger,
        )
        return resolution

    def register_scientific_execution_authority(
        registry: ArtifactRegistry,
        ledger: EventLedger,
        *,
        preparation_artifact_sha256: str,
        output_manifest_artifact_sha256: str,
        environment_artifact_sha256: str,
        isolation_attestation_artifact_sha256: str,
        backend_attestation_artifact_sha256: str,
        execution_activity_artifact_sha256: str | None = None,
        expected_ledger_run_id: str,
        expected_execution_run_id: str,
    ) -> ArtifactRecord:
        entry_registry, entry_ledger = _locked_scientific_execution_snapshot(
            registry,
            ledger,
            expected_ledger_run_id,
        )
        candidate = load_candidate(
            registry,
            ledger,
            preparation_artifact_sha256=preparation_artifact_sha256,
            output_manifest_artifact_sha256=output_manifest_artifact_sha256,
            environment_artifact_sha256=environment_artifact_sha256,
            isolation_attestation_artifact_sha256=(
                isolation_attestation_artifact_sha256
            ),
            backend_attestation_artifact_sha256=backend_attestation_artifact_sha256,
            execution_activity_artifact_sha256=(
                execution_activity_artifact_sha256
            ),
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
        )
        profile = candidate.preparation.backend_profile
        if profile.backend_id in categorically_unsupported:
            raise unavailable_error(
                "UNSUPPORTED: BACKEND_CATEGORICALLY_NON_SCIENTIFIC"
            )
        verifier = verifier_map.get(profile.key)
        if verifier is None:
            raise unavailable_error(
                "BLOCKED_EXTERNAL: BACKEND_ATTESTATION_VERIFIER_UNAVAILABLE"
            )
        claim_sha256 = verify_candidate(registry, candidate, verifier)
        source_records = authority_source_records(registry, candidate)
        source_hashes = tuple(item.sha256 for item in source_records)
        existing = authority_records_for_slot(registry, candidate)
        if len(existing) > 1:
            raise ExperimentError("scientific execution authority slot is ambiguous")
        authority_id = authority_identity(candidate, claim_sha256)
        binding = authority_binding(
            candidate,
            authority_id=authority_id,
            claim_sha256=claim_sha256,
            source_records=source_records,
        )
        admitted = authority_events_for_slot(entry_ledger.events, candidate)
        if len(admitted) > 1:
            raise ExperimentError("scientific execution authority event is ambiguous")
        publications = authority_publications_for_slot(
            entry_ledger.events,
            candidate,
        )
        if len(publications) > 1:
            raise ExperimentError(
                "scientific execution authority publication slot is ambiguous"
            )
        if publications and (not admitted or not existing):
            raise ExperimentError(
                "scientific execution authority publication is incomplete"
            )
        if existing and not admitted:
            raise ExperimentError(
                "scientific execution authority artifact lacks its verification event"
            )
        registry_guard = registry._open_mutation_lock()
        try:
            ledger_guard = ledger._open_lock()
            try:
                locked_registry = registry._verify_all_locked(
                    registry_guard,
                    raise_on_error=True,
                )
                locked_ledger = ledger._validate_bytes(
                    ledger._read_raw_locked(ledger_guard)
                )
                if (
                    locked_registry != entry_registry
                    or locked_ledger != entry_ledger
                    or not locked_ledger.valid
                ):
                    raise ExperimentError(
                        "scientific execution sources changed before authority admission"
                    )
                events_needed = int(not admitted) + int(not publications)
                _require_scientific_execution_capacity(
                    locked_registry,
                    locked_ledger,
                    registry_records_needed=int(not existing),
                    ledger_events_needed=events_needed,
                )
                if admitted:
                    event_index, event, admitted_binding = admitted[0]
                    if dict(admitted_binding) != binding:
                        raise ExperimentError(
                            "scientific execution authority recovery differs from the admitted event"
                        )
                    verification_ledger = locked_ledger
                else:

                    def build_authority_event(
                        current: LedgerValidationResult,
                    ) -> LedgerEvent:
                        if current != locked_ledger:
                            raise ExperimentError(
                                "scientific execution ledger changed before verification"
                            )
                        current_state = (
                            current.events[-1].state_after
                            if current.events
                            else MacroState.PREFLIGHT
                        )
                        candidate_event = LedgerEvent.create(
                            run_id=expected_ledger_run_id,
                            actor_role=Role.CLAIM_VERIFIER,
                            state_before=current_state,
                            requested_state_after=current_state,
                            artifact_hashes=source_hashes,
                            code_version=f"sha256:{candidate.spec.code_sha256}",
                            configuration_hash=(
                                candidate.spec.configuration_sha256
                            ),
                            dataset_identifiers=(candidate.spec.data_sha256,),
                            random_seeds=candidate.spec.seeds,
                            evaluator_outputs=tuple(
                                item.sha256 for item in candidate.output_records
                            ),
                            reason=(
                                "verified one exact independently attested scientific "
                                "execution against its prospective protocol and complete "
                                "output closure"
                            ),
                            prior_event_hash=current.head_hash,
                            event_type="CHECKPOINT",
                            metadata={
                                "scientific_execution_authority": binding
                            },
                        )
                        _require_scientific_execution_event_bound(candidate_event)
                        return candidate_event

                    event = ledger._append_locked(
                        ledger_guard,
                        build_authority_event,
                    )
                    verification_ledger = ledger._validate_bytes(
                        ledger._read_raw_locked(ledger_guard)
                    )
                    if not verification_ledger.valid:
                        raise ExperimentError(
                            "scientific execution verification corrupted the ledger"
                        )
                    event_index = len(verification_ledger.events) - 1
                validate_authority_event(
                    event,
                    event_index,
                    verification_ledger.events,
                    candidate=candidate,
                    binding=binding,
                    source_records=source_records,
                )
                authority = authority_from_event(
                    candidate,
                    authority_id=authority_id,
                    claim_sha256=claim_sha256,
                    event=event,
                    event_index=event_index,
                )
                authority_bytes = canonical_json_bytes(authority.to_dict()) + b"\n"
                expected_authority_sha256 = hashlib.sha256(
                    authority_bytes
                ).hexdigest()
                if existing and existing[0].sha256 != expected_authority_sha256:
                    raise ExperimentError(
                        "scientific execution authority recovery artifact is competing"
                    )
                record = registry._put_bytes_locked(
                    registry_guard,
                    authority_bytes,
                    logical_type=SCIENTIFIC_EXECUTION_AUTHORITY_LOGICAL_TYPE,
                    origin=_SCIENTIFIC_EXECUTION_AUTHORITY_ORIGIN,
                    creator_role=Role.CLAIM_VERIFIER,
                    creation_command=_SCIENTIFIC_EXECUTION_AUTHORITY_COMMAND,
                    parent_artifacts=authority.source_artifact_hashes,
                    schema_version="1.0",
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                    created_at=None,
                )
                publication_binding = (
                    _scientific_execution_authority_publication_binding(
                        record,
                        authority,
                    )
                )
                if publications:
                    publication_index, publication_event, stated = publications[0]
                    if dict(stated) != publication_binding:
                        raise ExperimentError(
                            "scientific execution authority publication recovery is competing"
                        )
                    committed_ledger = verification_ledger
                else:

                    def build_publication_event(
                        current: LedgerValidationResult,
                    ) -> LedgerEvent:
                        if current != verification_ledger:
                            raise ExperimentError(
                                "scientific execution ledger changed before publication"
                            )
                        current_state = current.events[-1].state_after
                        candidate_event = LedgerEvent.create(
                            run_id=expected_ledger_run_id,
                            actor_role=Role.CLAIM_VERIFIER,
                            state_before=current_state,
                            requested_state_after=current_state,
                            artifact_hashes=(record.sha256,),
                            code_version=f"sha256:{candidate.spec.code_sha256}",
                            configuration_hash=(
                                candidate.spec.configuration_sha256
                            ),
                            dataset_identifiers=(candidate.spec.data_sha256,),
                            random_seeds=candidate.spec.seeds,
                            evaluator_outputs=(),
                            reason=(
                                "published the exact source-owned scientific execution authority"
                            ),
                            prior_event_hash=current.head_hash,
                            event_type="CHECKPOINT",
                            metadata={
                                "scientific_execution_authority_publication": (
                                    publication_binding
                                )
                            },
                        )
                        _require_scientific_execution_event_bound(candidate_event)
                        return candidate_event

                    publication_event = ledger._append_locked(
                        ledger_guard,
                        build_publication_event,
                    )
                    committed_ledger = ledger._validate_bytes(
                        ledger._read_raw_locked(ledger_guard)
                    )
                    if not committed_ledger.valid:
                        raise ExperimentError(
                            "scientific execution publication corrupted the ledger"
                        )
                    publication_index = len(committed_ledger.events) - 1
                _validate_scientific_execution_authority_publication_event(
                    publication_event,
                    publication_index,
                    committed_ledger.events,
                    record=record,
                    authority=authority,
                    candidate=candidate,
                )
                final_registry = registry._verify_all_locked(
                    registry_guard,
                    raise_on_error=True,
                )
                final_ledger = ledger._validate_bytes(
                    ledger._read_raw_locked(ledger_guard)
                )
                if (
                    final_registry.count
                    != locked_registry.count + int(not existing)
                    or final_ledger != committed_ledger
                ):
                    raise ExperimentError(
                        "scientific execution authority changed during admission"
                    )
            finally:
                ledger._unlock(ledger_guard)
        finally:
            registry._unlock_mutation(registry_guard)
        require_scientific_execution_authority(
            registry,
            ledger,
            authority_artifact_sha256=record.sha256,
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
        )
        return record

    def require_scientific_execution_authority(
        registry: ArtifactRegistry,
        ledger: EventLedger,
        *,
        authority_artifact_sha256: str,
        expected_ledger_run_id: str,
        expected_execution_run_id: str,
    ) -> ScientificExecutionAuthority:
        entry_registry, entry_ledger = _locked_scientific_execution_snapshot(
            registry,
            ledger,
            expected_ledger_run_id,
        )
        validate_identifier(expected_execution_run_id, "expected execution run ID")
        record, value, _ = load_json(
            registry,
            authority_artifact_sha256,
            logical_type=SCIENTIFIC_EXECUTION_AUTHORITY_LOGICAL_TYPE,
            creator_role=Role.CLAIM_VERIFIER,
        )
        if (
            record.origin != _SCIENTIFIC_EXECUTION_AUTHORITY_ORIGIN
            or record.creation_command != _SCIENTIFIC_EXECUTION_AUTHORITY_COMMAND
        ):
            raise ExperimentError(
                "scientific execution authority metadata is not source-owned"
            )
        authority = authority_type.from_mapping(value)
        if (
            authority.ledger_run_id != expected_ledger_run_id
            or authority.execution_run_id != expected_execution_run_id
            or record.parent_artifacts != authority.source_artifact_hashes
        ):
            raise ExperimentError("scientific execution authority names another closure")
        verifier = verifier_map.get(authority.backend_profile.key)
        if verifier is None:
            raise unavailable_error(
                "scientific execution authority has no production source-owned verifier"
            )
        candidate = load_candidate(
            registry,
            ledger,
            preparation_artifact_sha256=authority.preparation_artifact_sha256,
            output_manifest_artifact_sha256=(
                authority.output_manifest_artifact_sha256
            ),
            environment_artifact_sha256=authority.environment_artifact_sha256,
            isolation_attestation_artifact_sha256=(
                authority.isolation_attestation_artifact_sha256
            ),
            backend_attestation_artifact_sha256=(
                authority.backend_attestation_artifact_sha256
            ),
            execution_activity_artifact_sha256=(
                authority.execution_activity_artifact_sha256
            ),
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
        )
        claim_sha256 = verify_candidate(registry, candidate, verifier)
        source_records = authority_source_records(registry, candidate)
        if record.parent_artifacts != tuple(item.sha256 for item in source_records):
            raise ExperimentError(
                "scientific execution authority source closure was substituted"
            )
        slot_records = authority_records_for_slot(registry, candidate)
        if slot_records != (record,):
            raise ExperimentError(
                "scientific execution authority artifact slot is ambiguous"
            )
        authority_id = authority_identity(candidate, claim_sha256)
        binding = authority_binding(
            candidate,
            authority_id=authority_id,
            claim_sha256=claim_sha256,
            source_records=source_records,
        )
        events = entry_ledger.events
        matches = authority_events_for_slot(events, candidate)
        if len(matches) != 1:
            raise ExperimentError(
                "scientific execution authority lacks one exact ledger event"
            )
        event_index, event, admitted_binding = matches[0]
        if dict(admitted_binding) != binding:
            raise ExperimentError(
                "scientific execution authority ledger event is competing"
            )
        validate_authority_event(
            event,
            event_index,
            events,
            candidate=candidate,
            binding=binding,
            source_records=source_records,
        )
        expected = authority_from_event(
            candidate,
            authority_id=authority_id,
            claim_sha256=claim_sha256,
            event=event,
            event_index=event_index,
        )
        if authority != expected:
            raise ExperimentError(
                "scientific execution authority differs from fresh source replay"
            )
        publications = authority_publications_for_slot(events, candidate)
        if len(publications) != 1:
            raise ExperimentError(
                "scientific execution authority lacks one exact publication"
            )
        publication_index, publication_event, published = publications[0]
        if dict(published) != _scientific_execution_authority_publication_binding(
            record,
            authority,
        ):
            raise ExperimentError(
                "scientific execution authority publication is competing"
            )
        _validate_scientific_execution_authority_publication_event(
            publication_event,
            publication_index,
            events,
            record=record,
            authority=authority,
            candidate=candidate,
        )
        _require_scientific_execution_snapshot_unchanged(
            registry,
            ledger,
            expected_ledger_run_id,
            entry_registry,
            entry_ledger,
        )
        return authority

    return (
        resolve_scientific_execution_authority,
        register_scientific_execution_authority,
        require_scientific_execution_authority,
    )


(
    resolve_scientific_execution_authority,
    register_scientific_execution_authority,
    require_scientific_execution_authority,
) = _build_scientific_execution_authority_api()
del _build_scientific_execution_authority_api


__all__ = [
    "AcceleratorKind",
    "AdaptiveExecutionPlan",
    "AblationResult",
    "CachePolicy",
    "CheckpointPolicy",
    "CollectedRun",
    "COMPUTE_ESCALATION_PLAN_AUTHORITY_LOGICAL_TYPE",
    "ComputeMode",
    "ComputeBackend",
    "ComputeEscalationBudget",
    "ComputeEscalationPlanAuthority",
    "COMPUTE_ESCALATION_SUBMISSION_AUTHORIZATION_LOGICAL_TYPE",
    "COMPUTE_ESCALATION_SUBMISSION_AUTHORIZATION_SCHEMA",
    "COMPUTE_ESCALATION_SUBMISSION_CONSUMPTION_SCHEMA",
    "ComputeProfile",
    "ConfirmatoryPolicyError",
    "EvidenceClass",
    "ExecutionResult",
    "ExperimentError",
    "ExperimentClass",
    "ExperimentIntegrityError",
    "ExperimentPhase",
    "EscalationDecision",
    "FakeGPUCloudBackend",
    "FrozenRunSpec",
    "GPUCloudBackend",
    "GPUCloudCapabilities",
    "GPUCloudSubmissionPlan",
    "GPURequeueLineage",
    "JobStatus",
    "LocalMacBackend",
    "LOCAL_MAC_EXECUTION_INPUT_BINDING_SCHEMA",
    "LocalMacIsolationMode",
    "NetworkUseStatus",
    "OutputArtifact",
    "OutputManifest",
    "ReproductionComparison",
    "ReproductionStatus",
    "RegisteredGPUArtifacts",
    "ResourceEstimate",
    "RunState",
    "SchedulerKind",
    "ScheduledGPUArtifactBundle",
    "ScheduledGPUCloudBackend",
    "ScheduledGPURecoveryBlocked",
    "ScheduledGPURequest",
    "ScheduledGPUStatus",
    "ScheduledGPUTransport",
    "SeedRunResult",
    "SeedRunStatus",
    "SCIENTIFIC_BACKEND_ATTESTATION_ENVELOPE_SCHEMA",
    "SCIENTIFIC_BACKEND_ATTESTATION_LOGICAL_TYPE",
    "SCIENTIFIC_BACKEND_EXECUTION_CLAIM_SCHEMA",
    "SCIENTIFIC_BACKEND_EXECUTION_CLAIM_SCHEMA_V2",
    "SCIENTIFIC_EXECUTION_AUTHORITY_EVENT_SCHEMA",
    "SCIENTIFIC_EXECUTION_AUTHORITY_LOGICAL_TYPE",
    "SCIENTIFIC_EXECUTION_AUTHORITY_PUBLICATION_EVENT_SCHEMA",
    "SCIENTIFIC_EXECUTION_AUTHORITY_SCHEMA",
    "SCIENTIFIC_EXECUTION_AUTHORITY_SCHEMA_V2",
    "SCIENTIFIC_EXECUTION_ACTIVITY_SCHEMA",
    "SCIENTIFIC_EXECUTION_ACTIVITY_LOGICAL_TYPE",
    "COMPLETE_GENERIC_ML_ACTIVITY_PROFILE",
    "SCIENTIFIC_EXECUTION_ENVIRONMENT_LOGICAL_TYPE",
    "SCIENTIFIC_EXECUTION_ENVIRONMENT_SCHEMA",
    "SCIENTIFIC_EXECUTION_INPUT_BINDING_LOGICAL_TYPE",
    "SCIENTIFIC_EXECUTION_INPUT_BINDING_SCHEMA",
    "SCIENTIFIC_EXECUTION_ISOLATION_LOGICAL_TYPE",
    "SCIENTIFIC_EXECUTION_ISOLATION_SCHEMA",
    "SCIENTIFIC_EXECUTION_PLAN_LOGICAL_TYPE",
    "SCIENTIFIC_EXECUTION_PLAN_SCHEMA",
    "SCIENTIFIC_EXECUTION_PREPARATION_EVENT_SCHEMA",
    "SCIENTIFIC_EXECUTION_PREPARATION_LOGICAL_TYPE",
    "SCIENTIFIC_EXECUTION_PREPARATION_SCHEMA",
    "SCIENTIFIC_EXECUTION_SYSTEM_FIXTURE_LOGICAL_TYPE",
    "SCIENTIFIC_METHOD_DEFINITION_BINDING_METADATA_KEY",
    "SCIENTIFIC_METHOD_DEFINITION_BINDING_PROFILE",
    "SCIENTIFIC_METHOD_DEFINITION_BINDING_SCHEMA",
    "ScientificBackendAttestationProfile",
    "ScientificExecutionAuthority",
    "ScientificExecutionActivityKind",
    "ScientificDatasetAccessPurpose",
    "ScientificExecutionTerminalKind",
    "ScientificExecutionArtifactBinding",
    "ScientificExecutionActivityRow",
    "ScientificExecutionActivityTerminal",
    "ScientificExecutionActivity",
    "ScientificExecutionAuthorityResolution",
    "ScientificExecutionAuthorityUnavailable",
    "ScientificExecutionOutcome",
    "ScientificExecutionPreparation",
    "ScientificExecutionVerificationStatus",
    "ScientificMethodDefinitionBinding",
    "ScientificReferenceWorkBinding",
    "StagedArtifact",
    "SubmissionConflictError",
    "SubmissionReceipt",
    "ValidationStatus",
    "compare_clean_rerun",
    "default_local_cpu_profile",
    "default_resource_estimate",
    "derive_scientific_execution_outcome",
    "make_gpu_cloud_submission_plan",
    "plan_adaptive_execution",
    "register_compute_escalation_plan_authority",
    "register_compute_escalation_submission_authorization",
    "register_scientific_execution_authority",
    "register_scientific_execution_preparation",
    "resolve_scientific_execution_authority",
    "resolve_scientific_method_definition_binding",
    "resolve_scientific_reference_work_binding",
    "resolve_scientific_statistical_use_binding",
    "SCIENTIFIC_STATISTICAL_USE_BINDING_METADATA_KEY",
    "SCIENTIFIC_STATISTICAL_USE_BINDING_SCHEMA",
    "SCIENTIFIC_REFERENCE_WORK_POLICY_METADATA_KEY",
    "require_compute_escalation_plan_authority",
    "require_scientific_execution_preparation",
    "require_scientific_execution_authority",
    "require_scientific_execution_activity",
    "require_scientific_execution_run_spec",
    "validate_scientific_execution_attestation_claim",
    "require_no_backend_fallback",
    "validate_compute_escalation",
    "validate_explicit_retry",
]
