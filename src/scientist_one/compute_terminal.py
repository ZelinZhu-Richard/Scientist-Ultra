"""Source-owned operational compute blockers with separate closed codecs.

The original wall-budget codec can authorize only a mandatory,
scientifically eligible workload that never started before its precommitted
run wall budget expired. The GPU-requirement codec binds one unperformed
mandatory CUDA-device protocol outside admitted LOCAL_MAC capabilities.
Neither establishes physical hardware incapacity, cloud availability,
scientific validity, or permission to spend external resources.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
from typing import TYPE_CHECKING, Any, Mapping

from .artifacts import MAX_REGISTRY_RECORDS, ArtifactRecord, ArtifactRegistry
from .errors import ArtifactError, ValidationError
from .cuda_device_timing import CUDA_DEVICE_TIMING_PROFILE_ID
from .experiments import (
    EvidenceClass,
    SCIENTIFIC_EXECUTION_AUTHORITY_LOGICAL_TYPE,
    SCIENTIFIC_EXECUTION_PREPARATION_LOGICAL_TYPE,
    FrozenRunSpec,
    require_scientific_execution_run_spec,
)
from .ledger import MAX_LEDGER_BYTES, MAX_LEDGER_EVENTS, EventLedger, LedgerEvent
from .models import (
    MacroState,
    TerminalState,
    thaw_json,
    utc_now,
    validate_identifier,
    validate_sha256,
)
from .orchestrator import (
    OrchestrationError,
    ResourceRuntimeWallBudgetObservation,
    _locked_resource_registry_ledger_snapshot,
    _project_resource_execution_lock,
    _require_resource_wall_observation_locked,
)
from .resources import ResourceConfig, resource_config_sha256
from .roles import Role
from .scientific_design import (
    EvaluationContract,
    EvaluationContractFreezeGateReceipt,
    ScientificPromotionError,
    require_evaluation_contract_freeze_gate_receipt,
    require_frozen_evaluation_contract,
)
from .security import canonical_json_bytes, safe_json_loads

if TYPE_CHECKING:
    from .gpu_validation_requirement import GpuValidationRequirement


COMPUTE_TERMINAL_ASSESSMENT_SCHEMA = "compute-terminal-assessment/v1"
COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE = "compute_terminal_assessment"
COMPUTE_TERMINAL_ASSESSMENT_ORIGIN = (
    "source-owned never-started run wall-budget exhaustion assessment"
)
COMPUTE_TERMINAL_ASSESSMENT_COMMAND = (
    "scientist-one",
    "assess-compute-terminal",
)
COMPUTE_TERMINAL_EVENT_KEY = "compute_terminal_assessment_authority"
WALL_BUDGET_EXHAUSTED_STATUS = (
    "WALL_BUDGET_EXHAUSTED_WITH_REQUIRED_WORK_INCOMPLETE"
)
MANDATORY_WORK_STATUS = "NOT_STARTED_INCOMPLETE"
EXTERNAL_EFFECT_STATUS = "NONE_OBSERVED"
COMPUTE_TERMINAL_AUTHORITY_SCOPE = "OPERATIONAL_BLOCKER"
_MAX_COMPUTE_TERMINAL_BYTES = 1024 * 1024
GPU_COMPUTE_TERMINAL_ASSESSMENT_SCHEMA = "compute-terminal-gpu-requirement/v1"
GPU_COMPUTE_TERMINAL_ASSESSMENT_ORIGIN = (
    "source-owned never-started mandatory CUDA-device protocol assessment"
)
GPU_PROTOCOL_REQUIRED_STATUS = "UNPERFORMED_MANDATORY_CUDA_DEVICE_PROTOCOL_REQUIRES_GPU_CLOUD"
GPU_REQUIREMENT_SCOPE = "ONE_MANDATORY_CUDA_DEVICE_TIMING_OBLIGATION"
_GPU_ASSESSMENT_REASON = (
    "verified unperformed mandatory CUDA-device protocol outside admitted LOCAL_MAC capabilities"
)
_PROGRESS_LOGICAL_TYPES = frozenset(
    {
        SCIENTIFIC_EXECUTION_PREPARATION_LOGICAL_TYPE,
        SCIENTIFIC_EXECUTION_AUTHORITY_LOGICAL_TYPE,
        "experiment_output_manifest",
        "scientific_execution_environment",
        "scientific_execution_isolation_attestation",
        "scientific_execution_backend_attestation",
    }
)


class ComputeTerminalError(RuntimeError):
    """The operational compute authority is unavailable or malformed."""


class ComputeTerminalAssessmentResolutionStatus(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    NONTERMINAL = "NONTERMINAL"
    BLOCKED_LOCAL = "BLOCKED_LOCAL"
    BLOCKED_EXTERNAL = "BLOCKED_EXTERNAL"


@dataclass(frozen=True, slots=True)
class ComputeTerminalAssessment:
    assessment_id: str
    ledger_run_id: str
    execution_run_id: str
    scientific_binding_sha256: str
    evaluation_contract_freeze_receipt_artifact_sha256: str
    evaluation_contract_freeze_receipt_record_hash: str
    contract_artifact_sha256: str
    contract_record_hash: str
    frozen_run_spec_artifact_sha256: str
    frozen_run_spec_record_hash: str
    frozen_configuration_inventory_artifact_sha256: str
    frozen_configuration_inventory_record_hash: str
    wall_budget_observation_artifact_sha256: str
    wall_budget_observation_record_hash: str
    resource_config: ResourceConfig
    resource_config_sha256: str
    external_resource_authority_sequence: int
    external_resource_authority_sha256: str
    maximum_wall_clock_seconds: float
    wall_started_at_epoch_seconds: float
    wall_observed_at_epoch_seconds: float
    wall_elapsed_seconds: float
    mandatory_work_status: str
    external_effect_status: str
    factual_status: str
    source_artifact_sha256s: tuple[str, ...]
    source_artifact_record_hashes: tuple[str, ...]
    ledger_event_id: str
    ledger_event_hash: str
    ledger_event_index: int
    ledger_prefix_head_hash: str
    authority_scope: str = COMPUTE_TERMINAL_AUTHORITY_SCOPE
    scientific_evidence: bool = False

    def __post_init__(self) -> None:
        for name in ("assessment_id", "ledger_run_id", "execution_run_id", "ledger_event_id"):
            validate_identifier(getattr(self, name), name.replace("_", " "))
        for name in (
            "scientific_binding_sha256",
            "evaluation_contract_freeze_receipt_artifact_sha256",
            "evaluation_contract_freeze_receipt_record_hash",
            "contract_artifact_sha256",
            "contract_record_hash",
            "frozen_run_spec_artifact_sha256",
            "frozen_run_spec_record_hash",
            "frozen_configuration_inventory_artifact_sha256",
            "frozen_configuration_inventory_record_hash",
            "wall_budget_observation_artifact_sha256",
            "wall_budget_observation_record_hash",
            "resource_config_sha256",
            "external_resource_authority_sha256",
            "ledger_event_hash",
            "ledger_prefix_head_hash",
        ):
            validate_sha256(getattr(self, name), name.replace("_", " "))
        if type(self.resource_config) is not ResourceConfig:
            raise ComputeTerminalError("compute assessment requires ResourceConfig")
        if self.resource_config_sha256 != resource_config_sha256(self.resource_config):
            raise ComputeTerminalError("compute assessment resource config hash differs")
        if (
            isinstance(self.external_resource_authority_sequence, bool)
            or not isinstance(self.external_resource_authority_sequence, int)
            or self.external_resource_authority_sequence < 1
            or isinstance(self.ledger_event_index, bool)
            or not isinstance(self.ledger_event_index, int)
            or self.ledger_event_index < 0
            or self.mandatory_work_status != MANDATORY_WORK_STATUS
            or self.external_effect_status != EXTERNAL_EFFECT_STATUS
            or self.factual_status != WALL_BUDGET_EXHAUSTED_STATUS
            or self.authority_scope != COMPUTE_TERMINAL_AUTHORITY_SCOPE
            or self.scientific_evidence is not False
            or self.ledger_prefix_head_hash != self.ledger_event_hash
            or self.maximum_wall_clock_seconds
            != self.resource_config.maximum_wall_clock_seconds
            or self.wall_elapsed_seconds < self.maximum_wall_clock_seconds
        ):
            raise ComputeTerminalError("compute terminal assessment claim is invalid")
        if (
            not isinstance(self.source_artifact_sha256s, tuple)
            or not isinstance(self.source_artifact_record_hashes, tuple)
            or len(self.source_artifact_sha256s) != 5
            or len(self.source_artifact_record_hashes) != 5
            or len(set(self.source_artifact_sha256s)) != 5
        ):
            raise ComputeTerminalError("compute assessment source closure is invalid")
        for digest in (*self.source_artifact_sha256s, *self.source_artifact_record_hashes):
            validate_sha256(digest, "compute terminal source identity")

    def to_dict(self) -> dict[str, Any]:
        result = {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if name != "resource_config"
        }
        result["schema_version"] = COMPUTE_TERMINAL_ASSESSMENT_SCHEMA
        result["resource_config"] = self.resource_config.to_dict()
        result["source_artifact_sha256s"] = list(self.source_artifact_sha256s)
        result["source_artifact_record_hashes"] = list(
            self.source_artifact_record_hashes
        )
        return result

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ComputeTerminalAssessment":
        expected = set(cls.__dataclass_fields__) | {"schema_version"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ComputeTerminalError("compute terminal assessment schema is invalid")
        if value["schema_version"] != COMPUTE_TERMINAL_ASSESSMENT_SCHEMA:
            raise ComputeTerminalError("unsupported compute terminal assessment schema")
        try:
            arguments = {name: value[name] for name in cls.__dataclass_fields__}
            arguments["resource_config"] = ResourceConfig.from_mapping(
                arguments["resource_config"]
            )
            arguments["source_artifact_sha256s"] = tuple(
                arguments["source_artifact_sha256s"]
            )
            arguments["source_artifact_record_hashes"] = tuple(
                arguments["source_artifact_record_hashes"]
            )
            return cls(**arguments)
        except (KeyError, TypeError, ValueError) as exc:
            raise ComputeTerminalError("compute terminal assessment is malformed") from exc


@dataclass(frozen=True, slots=True)
class ComputeTerminalAssessmentResolution:
    status: ComputeTerminalAssessmentResolutionStatus
    reason_code: str
    assessment: ComputeTerminalAssessment | None = None
    assessment_artifact_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ComputeTerminalAssessmentResolutionStatus):
            raise ComputeTerminalError("compute terminal resolution status is invalid")
        if not isinstance(self.reason_code, str) or not self.reason_code:
            raise ComputeTerminalError("compute terminal resolution reason is invalid")
        if self.status is ComputeTerminalAssessmentResolutionStatus.AUTHORIZED:
            if self.assessment is not None and self.assessment_artifact_sha256 is None:
                raise ComputeTerminalError("registered compute authority lacks artifact")
        elif self.assessment is not None or self.assessment_artifact_sha256 is not None:
            raise ComputeTerminalError("blocked compute resolution cannot carry authority")


@dataclass(frozen=True, slots=True)
class GpuRequirementComputeTerminalAssessment:
    """Operational source-bound codec; decoding alone confers no authority.

    The requirement is one frozen device-specific measurement obligation,
    not physical CPU incapacity, cloud availability or scientific adequacy.
    No wall-budget fields are fabricated or borrowed from the v1 codec.
    """

    assessment_id: str
    ledger_run_id: str
    execution_run_id: str
    hypothesis_id: str
    experiment_id: str
    scientific_binding_sha256: str
    project_definition_sha256: str
    contract_value_sha256: str
    evaluation_contract_freeze_receipt_artifact_sha256: str
    evaluation_contract_freeze_receipt_record_hash: str
    contract_artifact_sha256: str
    contract_record_hash: str
    frozen_run_spec_artifact_sha256: str
    frozen_run_spec_record_hash: str
    compute_escalation_plan_authority_artifact_sha256: str
    compute_escalation_plan_authority_record_hash: str
    cloud_run_spec_sha256: str
    local_compute_profile_sha256: str
    cloud_compute_profile_sha256: str
    freeze_event_id: str
    freeze_event_hash: str
    freeze_event_index: int
    escalation_event_id: str
    escalation_event_hash: str
    escalation_event_index: int
    source_artifact_sha256s: tuple[str, ...]
    source_artifact_record_hashes: tuple[str, ...]
    ledger_event_id: str
    ledger_event_hash: str
    ledger_event_index: int
    ledger_prefix_head_hash: str
    requirement_profile_id: str = CUDA_DEVICE_TIMING_PROFILE_ID
    requirement_scope: str = GPU_REQUIREMENT_SCOPE
    mandatory_work_status: str = MANDATORY_WORK_STATUS
    external_effect_status: str = EXTERNAL_EFFECT_STATUS
    factual_status: str = GPU_PROTOCOL_REQUIRED_STATUS
    authority_scope: str = COMPUTE_TERMINAL_AUTHORITY_SCOPE
    external_validation_status: str = "UNTESTED"
    scientific_evidence: bool = False
    spending_authorized: bool = False

    def __post_init__(self) -> None:
        if type(self) is not GpuRequirementComputeTerminalAssessment:
            raise ComputeTerminalError("GPU compute codec requires its exact native type")
        identifiers = {
            "assessment_id", "ledger_run_id", "execution_run_id", "hypothesis_id",
            "experiment_id", "freeze_event_id", "escalation_event_id", "ledger_event_id",
        }
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if name in identifiers:
                if type(value) is not str:
                    raise ComputeTerminalError("GPU compute identity must be native text")
                validate_identifier(value, name)
            elif name.endswith(("_sha256", "_hash")):
                if type(value) is not str:
                    raise ComputeTerminalError("GPU compute hash must be native text")
                validate_sha256(value, name)
            elif name.endswith("_index"):
                if type(value) is not int or not 0 <= value < MAX_LEDGER_EVENTS:
                    raise ComputeTerminalError("GPU compute event index is invalid")
        constants = {
            "requirement_profile_id": CUDA_DEVICE_TIMING_PROFILE_ID,
            "requirement_scope": GPU_REQUIREMENT_SCOPE,
            "mandatory_work_status": MANDATORY_WORK_STATUS,
            "external_effect_status": EXTERNAL_EFFECT_STATUS,
            "factual_status": GPU_PROTOCOL_REQUIRED_STATUS,
            "authority_scope": COMPUTE_TERMINAL_AUTHORITY_SCOPE,
            "external_validation_status": "UNTESTED",
        }
        if any(type(getattr(self, key)) is not str or getattr(self, key) != value
               for key, value in constants.items()):
            raise ComputeTerminalError("GPU compute scope or factual status differs")
        if (self.scientific_evidence is not False or self.spending_authorized is not False
                or self.ledger_prefix_head_hash != self.ledger_event_hash
                or self.freeze_event_index >= self.ledger_event_index
                or self.escalation_event_index >= self.ledger_event_index):
            raise ComputeTerminalError("GPU compute authority or chronology is invalid")
        digests, records = self.source_artifact_sha256s, self.source_artifact_record_hashes
        # The downstream terminal adds this assessment to its evidence parents.
        if (type(digests) is not tuple or type(records) is not tuple
                or not 1 <= len(digests) <= 255 or len(records) != len(digests)
                or any(type(value) is not str for value in (*digests, *records))
                or len(set(digests)) != len(digests)):
            raise ComputeTerminalError("GPU compute source closure is invalid")
        for value in (*digests, *records):
            validate_sha256(value, "GPU compute source")
        source_map = dict(zip(digests, records, strict=True))
        for digest, record in (
            (self.evaluation_contract_freeze_receipt_artifact_sha256,
             self.evaluation_contract_freeze_receipt_record_hash),
            (self.contract_artifact_sha256, self.contract_record_hash),
            (self.frozen_run_spec_artifact_sha256, self.frozen_run_spec_record_hash),
            (self.compute_escalation_plan_authority_artifact_sha256,
             self.compute_escalation_plan_authority_record_hash),
        ):
            if source_map.get(digest) != record:
                raise ComputeTerminalError("GPU compute named source is outside its closure")

    def to_dict(self) -> dict[str, Any]:
        GpuRequirementComputeTerminalAssessment.__post_init__(self)
        result = {name: getattr(self, name) for name in self.__dataclass_fields__}
        result["schema_version"] = GPU_COMPUTE_TERMINAL_ASSESSMENT_SCHEMA
        result["source_artifact_sha256s"] = list(self.source_artifact_sha256s)
        result["source_artifact_record_hashes"] = list(self.source_artifact_record_hashes)
        return result

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> GpuRequirementComputeTerminalAssessment:
        if (cls is not GpuRequirementComputeTerminalAssessment or type(value) is not dict
                or any(type(key) is not str for key in value)
                or set(value) != set(cls.__dataclass_fields__) | {"schema_version"}
                or type(value["schema_version"]) is not str
                or value["schema_version"] != GPU_COMPUTE_TERMINAL_ASSESSMENT_SCHEMA):
            raise ComputeTerminalError("GPU compute assessment schema is invalid")
        arguments = {name: value[name] for name in cls.__dataclass_fields__}
        for key in ("source_artifact_sha256s", "source_artifact_record_hashes"):
            if type(arguments[key]) is not list or not 1 <= len(arguments[key]) <= 255:
                raise ComputeTerminalError("GPU compute source wire must use native arrays")
            arguments[key] = tuple(arguments[key])
        return cls(**arguments)


@dataclass(frozen=True, slots=True)
class _ComputeSources:
    freeze_record: ArtifactRecord
    freeze: EvaluationContractFreezeGateReceipt
    contract_record: ArtifactRecord
    contract: EvaluationContract
    spec_record: ArtifactRecord
    spec: FrozenRunSpec
    inventory_record: ArtifactRecord
    observation_record: ArtifactRecord
    observation: ResourceRuntimeWallBudgetObservation
    registry_snapshot: Any
    ledger_snapshot: Any

    @property
    def records(self) -> tuple[ArtifactRecord, ...]:
        return (
            self.freeze_record,
            self.contract_record,
            self.spec_record,
            self.inventory_record,
            self.observation_record,
        )


@dataclass(frozen=True, slots=True)
class _GpuComputeSources:
    requirement: GpuValidationRequirement

    @property
    def records(self) -> tuple[ArtifactRecord, ...]:
        return self.requirement.source_records

    @property
    def spec(self) -> FrozenRunSpec:
        return self.requirement.local_spec

    @property
    def registry_snapshot(self) -> Any:
        return self.requirement.entry_registry_snapshot

    @property
    def ledger_snapshot(self) -> Any:
        return self.requirement.entry_ledger_snapshot


def _load_json_record(
    registry: ArtifactRegistry,
    digest: str,
    *,
    logical_type: str,
    creator_role: Role,
) -> tuple[ArtifactRecord, Mapping[str, Any]]:
    validate_sha256(digest, f"{logical_type} SHA-256")
    try:
        registry.verify(digest, raise_on_error=True)
        record = registry.get_metadata(digest)
        raw = registry.get_bytes(digest)
        value = safe_json_loads(raw)
    except (ArtifactError, ValidationError) as exc:
        raise ComputeTerminalError(f"{logical_type} cannot be reopened") from exc
    if (
        record.logical_type != logical_type
        or record.creator_role is not creator_role
        or record.validation_result != "PASS"
        or not record.frozen
        or record.record_hash is None
        or not isinstance(value, Mapping)
        or raw != canonical_json_bytes(value) + b"\n"
    ):
        raise ComputeTerminalError(f"{logical_type} is not exact source authority")
    return record, value


def _contains_key(value: object, key: str, *, depth: int = 0) -> bool:
    if depth > 16:
        raise ComputeTerminalError("ledger metadata nesting exceeds safety bound")
    if isinstance(value, Mapping):
        return key in value or any(
            _contains_key(item, key, depth=depth + 1) for item in value.values()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_key(item, key, depth=depth + 1) for item in value)
    return False


def _utc_epoch_seconds(value: str, label: str) -> float:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ComputeTerminalError(f"{label} timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except (OverflowError, OSError, ValueError) as exc:
        raise ComputeTerminalError(f"{label} timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ComputeTerminalError(f"{label} timestamp is not UTC")
    try:
        return parsed.timestamp()
    except (OverflowError, OSError, ValueError) as exc:
        raise ComputeTerminalError(f"{label} timestamp is invalid") from exc


def _contains_value(value: object, target: str, *, depth: int = 0) -> bool:
    if depth > 16:
        raise ComputeTerminalError("ledger metadata nesting exceeds safety bound")
    if value == target:
        return True
    if isinstance(value, Mapping):
        return any(
            _contains_value(item, target, depth=depth + 1)
            for item in value.values()
        )
    if isinstance(value, (list, tuple)):
        return any(
            _contains_value(item, target, depth=depth + 1) for item in value
        )
    return False


def _record_descends_from(
    registry: ArtifactRegistry,
    record: ArtifactRecord,
    roots: frozenset[str],
) -> bool:
    pending = list(record.parent_artifacts)
    seen: set[str] = set()
    while pending:
        digest = pending.pop()
        if digest in roots:
            return True
        if digest in seen:
            continue
        seen.add(digest)
        if len(seen) > 2048:
            raise ComputeTerminalError("scientific progress graph exceeds safety bound")
        try:
            parent = registry.get_metadata(digest)
        except ArtifactError as exc:
            raise ComputeTerminalError("scientific progress parent is unavailable") from exc
        pending.extend(parent.parent_artifacts)
    return False


def _has_scientific_execution_progress(
    registry: ArtifactRegistry,
    events: tuple[LedgerEvent, ...],
    *,
    selected_spec_record: ArtifactRecord,
    selected_spec: FrozenRunSpec,
) -> bool:
    matching_spec_hashes: set[str] = {selected_spec_record.sha256}
    records = registry.list_records()
    for record in records:
        if record.logical_type != "frozen_run_spec":
            continue
        try:
            candidate = require_scientific_execution_run_spec(
                registry,
                frozen_run_spec_artifact_sha256=record.sha256,
            )
        except Exception as exc:
            raise ComputeTerminalError(
                "a frozen run spec cannot be excluded from progress replay"
            ) from exc
        if candidate.scientific_binding_sha256 == selected_spec.scientific_binding_sha256:
            matching_spec_hashes.add(record.sha256)
    roots = frozenset(matching_spec_hashes)
    progress_hashes: set[str] = set()
    for record in records:
        progress_type = (
            record.logical_type in _PROGRESS_LOGICAL_TYPES
            or record.logical_type.startswith("experiment_output_")
            or record.logical_type.startswith("experiment_output.")
            or record.logical_type.startswith("scientific_execution_")
        )
        if progress_type and _record_descends_from(registry, record, roots):
            progress_hashes.add(record.sha256)
    if progress_hashes:
        return True
    for event in events:
        metadata = event.metadata
        if _contains_value(metadata, selected_spec.scientific_binding_sha256) and any(
            isinstance(key, str) and key.startswith("scientific_execution")
            for key in metadata
        ):
            return True
        if any(digest in event.artifact_hashes for digest in progress_hashes):
            return True
    return False


def _derive_sources(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    evaluation_contract_freeze_receipt_artifact_sha256: str,
    frozen_configuration_inventory_artifact_sha256: str,
    wall_budget_observation_artifact_sha256: str,
) -> tuple[ComputeTerminalAssessmentResolutionStatus, str, _ComputeSources | None]:
    entry_registry, entry_ledger = _locked_resource_registry_ledger_snapshot(
        registry, ledger, expected_ledger_run_id
    )
    for digest in (
        evaluation_contract_freeze_receipt_artifact_sha256,
        frozen_configuration_inventory_artifact_sha256,
        wall_budget_observation_artifact_sha256,
    ):
        try:
            registry.get_metadata(digest)
        except ArtifactError:
            return (
                ComputeTerminalAssessmentResolutionStatus.BLOCKED_LOCAL,
                "LOCAL_SOURCE_AUTHORITY_ABSENT",
                None,
            )
    try:
        freeze_record, freeze_value = _load_json_record(
            registry,
            evaluation_contract_freeze_receipt_artifact_sha256,
            logical_type="evaluation_contract_freeze_gate_receipt",
            creator_role=Role.CLAIM_VERIFIER,
        )
        freeze_candidate = EvaluationContractFreezeGateReceipt.from_dict(freeze_value)
        freeze = require_evaluation_contract_freeze_gate_receipt(
            registry,
            ledger,
            receipt_artifact_sha256=freeze_record.sha256,
            expected_run_id=expected_ledger_run_id,
            expected_contract_id=freeze_candidate.object_id,
        )
        contract = require_frozen_evaluation_contract(
            registry,
            contract_artifact_sha256=freeze.contract_artifact_sha256,
        )
        contract_record = registry.get_metadata(freeze.contract_artifact_sha256)
        spec = require_scientific_execution_run_spec(
            registry,
            frozen_run_spec_artifact_sha256=freeze.frozen_run_spec_artifact_sha256,
        )
        spec_record = registry.get_metadata(freeze.frozen_run_spec_artifact_sha256)
        from .gpu_validation_requirement import GPU_VALIDATION_REQUIREMENT_POLICY_METADATA_KEY

        # Prospective source policy, never publication order, selects this
        # compute family. Presence (including malformed values) must not
        # downgrade a declared device obligation into the legacy wall route.
        if GPU_VALIDATION_REQUIREMENT_POLICY_METADATA_KEY in spec.metadata:
            if _locked_resource_registry_ledger_snapshot(
                registry, ledger, expected_ledger_run_id,
            ) != (entry_registry, entry_ledger):
                raise ComputeTerminalError("compute route sources changed during resolution")
            return (
                ComputeTerminalAssessmentResolutionStatus.BLOCKED_LOCAL,
                "GPU_REQUIREMENT_POLICY_PRECLUDES_WALL_FALLBACK",
                None,
            )
        observation = _require_resource_wall_observation_locked(
            registry,
            ledger,
            observation_artifact_sha256=wall_budget_observation_artifact_sha256,
            expected_run_id=expected_ledger_run_id,
            project_lock_held=True,
        )
        observation_record = registry.get_metadata(
            wall_budget_observation_artifact_sha256
        )
        inventory_record = registry.get_metadata(
            frozen_configuration_inventory_artifact_sha256
        )
    except (OrchestrationError, ScientificPromotionError, ArtifactError) as exc:
        raise ComputeTerminalError(
            "compute terminal source authority is malformed or substituted"
        ) from exc
    if freeze.design_freeze_event_index >= len(entry_ledger.events):
        return (
            ComputeTerminalAssessmentResolutionStatus.BLOCKED_LOCAL,
            "DESIGN_FREEZE_EVENT_IS_OUTSIDE_THE_LEDGER",
            None,
        )
    freeze_event = entry_ledger.events[freeze.design_freeze_event_index]
    freeze_epoch_seconds = _utc_epoch_seconds(
        freeze_event.timestamp,
        "design freeze",
    )
    wall_deadline_epoch_seconds = (
        observation.runtime_state.wall_started_at_epoch_seconds
        + observation.resource_config.maximum_wall_clock_seconds
    )
    if (
        freeze.run_id != expected_ledger_run_id
        or spec.run_id != expected_execution_run_id
        or spec.evidence_class is not EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE
        or spec.seeds != contract.seed_reporting.seeds
        or freeze.experiment_plan_artifact_sha256s == ()
        or observation.frozen_configuration_inventory_artifact_sha256
        != frozen_configuration_inventory_artifact_sha256
        or inventory_record.record_hash
        != observation.frozen_configuration_inventory_record_hash
        or freeze_event.event_id != freeze.design_freeze_event_id
        or freeze_event.event_hash != freeze.design_freeze_event_hash
        or freeze.design_freeze_event_index >= observation.ledger_event_index
        or freeze_epoch_seconds >= wall_deadline_epoch_seconds
        or observation.runtime_state.wall_elapsed_seconds
        < observation.resource_config.maximum_wall_clock_seconds
    ):
        return (
            ComputeTerminalAssessmentResolutionStatus.BLOCKED_LOCAL,
            "LOCAL_SOURCE_CLOSURE_MISMATCH",
            None,
        )
    if (
        observation.ledger_event_index >= len(entry_ledger.events)
        or any(
            isinstance(event.state_before, TerminalState)
            or isinstance(event.requested_state_after, TerminalState)
            for event in entry_ledger.events
        )
    ):
        return (
            ComputeTerminalAssessmentResolutionStatus.BLOCKED_LOCAL,
            "PRIOR_TERMINAL_CAUSE_PRECLUDES_WALL_EXHAUSTION_AUTHORITY",
            None,
        )
    if any(
        _contains_key(event.metadata, "compute_escalation_submission_consumption")
        for event in entry_ledger.events
    ):
        return (
            ComputeTerminalAssessmentResolutionStatus.BLOCKED_EXTERNAL,
            "EXTERNAL_COMPUTE_EFFECT_PRESENT",
            None,
        )
    if _has_scientific_execution_progress(
        registry,
        entry_ledger.events,
        selected_spec_record=spec_record,
        selected_spec=spec,
    ):
        return (
            ComputeTerminalAssessmentResolutionStatus.NONTERMINAL,
            "MANDATORY_WORK_HAS_EXECUTION_EVIDENCE",
            None,
        )
    from .seed_reporting import (
        OperationalSeedReportingError,
        reject_operational_seed_exposure,
    )

    try:
        reject_operational_seed_exposure(
            registry, entry_registry.records, entry_ledger.events,
            complete_registry_population=True,
        )
    except OperationalSeedReportingError:
        # An unresolved non-isolated reservation cannot establish that this
        # mandatory work ran, but it also cannot support a no-progress terminal.
        return (
            ComputeTerminalAssessmentResolutionStatus.BLOCKED_LOCAL,
            "OPERATIONAL_RESERVATION_OR_POSSIBLE_PROGRESS",
            None,
        )
    final_registry, final_ledger = _locked_resource_registry_ledger_snapshot(
        registry, ledger, expected_ledger_run_id
    )
    if final_registry != entry_registry or final_ledger != entry_ledger:
        raise ComputeTerminalError(
            "compute terminal sources changed during fresh resolution"
        )
    return (
        ComputeTerminalAssessmentResolutionStatus.AUTHORIZED,
        WALL_BUDGET_EXHAUSTED_STATUS,
        _ComputeSources(
            freeze_record=freeze_record,
            freeze=freeze,
            contract_record=contract_record,
            contract=contract,
            spec_record=spec_record,
            spec=spec,
            inventory_record=inventory_record,
            observation_record=observation_record,
            observation=observation,
            registry_snapshot=entry_registry,
            ledger_snapshot=entry_ledger,
        ),
    )


def resolve_compute_terminal_assessment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    assessment_id: str,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    evaluation_contract_freeze_receipt_artifact_sha256: str,
    frozen_configuration_inventory_artifact_sha256: str,
    wall_budget_observation_artifact_sha256: str,
) -> ComputeTerminalAssessmentResolution:
    validate_identifier(assessment_id, "compute terminal assessment ID")
    validate_identifier(expected_ledger_run_id, "compute terminal ledger run ID")
    validate_identifier(expected_execution_run_id, "compute terminal execution run ID")
    with _project_resource_execution_lock(registry.policy.root):
        status, reason, _sources = _derive_sources(
            registry,
            ledger,
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
            evaluation_contract_freeze_receipt_artifact_sha256=(
                evaluation_contract_freeze_receipt_artifact_sha256
            ),
            frozen_configuration_inventory_artifact_sha256=(
                frozen_configuration_inventory_artifact_sha256
            ),
            wall_budget_observation_artifact_sha256=(
                wall_budget_observation_artifact_sha256
            ),
        )
    return ComputeTerminalAssessmentResolution(status=status, reason_code=reason)


def _assessment_event_binding(
    assessment_id: str,
    sources: _ComputeSources | _GpuComputeSources,
) -> dict[str, Any]:
    if type(sources) is _GpuComputeSources:
        requirement = sources.requirement
        return {
            "schema_version": GPU_COMPUTE_TERMINAL_ASSESSMENT_SCHEMA,
            "assessment_id": assessment_id,
            "ledger_run_id": requirement.freeze.run_id,
            "execution_run_id": sources.spec.run_id,
            "scientific_binding_sha256": sources.spec.scientific_binding_sha256,
            "project_definition_sha256": requirement.project_definition_sha256,
            "obligation_identity": list(requirement.obligation_identity),
            "requirement_profile_id": CUDA_DEVICE_TIMING_PROFILE_ID,
            "requirement_scope": GPU_REQUIREMENT_SCOPE,
            "source_artifact_sha256s": [record.sha256 for record in sources.records],
            "source_artifact_record_hashes": [str(record.record_hash) for record in sources.records],
            "factual_status": GPU_PROTOCOL_REQUIRED_STATUS,
            "mandatory_work_status": MANDATORY_WORK_STATUS,
            "external_effect_status": EXTERNAL_EFFECT_STATUS,
            "authority_scope": COMPUTE_TERMINAL_AUTHORITY_SCOPE,
            "external_validation_status": "UNTESTED",
            "scientific_evidence": False,
            "spending_authorized": False,
        }
    records = sources.records
    return {
        "schema_version": COMPUTE_TERMINAL_ASSESSMENT_SCHEMA,
        "assessment_id": assessment_id,
        "ledger_run_id": sources.freeze.run_id,
        "execution_run_id": sources.spec.run_id,
        "scientific_binding_sha256": sources.spec.scientific_binding_sha256,
        "source_artifact_sha256s": [record.sha256 for record in records],
        "source_artifact_record_hashes": [
            str(record.record_hash) for record in records
        ],
        "factual_status": WALL_BUDGET_EXHAUSTED_STATUS,
        "mandatory_work_status": MANDATORY_WORK_STATUS,
        "external_effect_status": EXTERNAL_EFFECT_STATUS,
        "authority_scope": COMPUTE_TERMINAL_AUTHORITY_SCOPE,
        "scientific_evidence": False,
    }


def _assessment_from_event(
    assessment_id: str,
    sources: _ComputeSources | _GpuComputeSources,
    event: LedgerEvent,
    event_index: int,
) -> ComputeTerminalAssessment | GpuRequirementComputeTerminalAssessment:
    if type(sources) is _GpuComputeSources:
        requirement = sources.requirement
        return GpuRequirementComputeTerminalAssessment(
            assessment_id=assessment_id,
            ledger_run_id=requirement.freeze.run_id,
            execution_run_id=sources.spec.run_id,
            hypothesis_id=sources.spec.hypothesis_id,
            experiment_id=sources.spec.experiment_id,
            scientific_binding_sha256=sources.spec.scientific_binding_sha256,
            project_definition_sha256=requirement.project_definition_sha256,
            contract_value_sha256=requirement.contract.sha256,
            evaluation_contract_freeze_receipt_artifact_sha256=requirement.freeze_record.sha256,
            evaluation_contract_freeze_receipt_record_hash=str(requirement.freeze_record.record_hash),
            contract_artifact_sha256=requirement.contract_record.sha256,
            contract_record_hash=str(requirement.contract_record.record_hash),
            frozen_run_spec_artifact_sha256=requirement.local_spec_record.sha256,
            frozen_run_spec_record_hash=str(requirement.local_spec_record.record_hash),
            compute_escalation_plan_authority_artifact_sha256=requirement.escalation_record.sha256,
            compute_escalation_plan_authority_record_hash=str(requirement.escalation_record.record_hash),
            cloud_run_spec_sha256=requirement.cloud_spec.sha256,
            local_compute_profile_sha256=sources.spec.compute_profile.sha256,
            cloud_compute_profile_sha256=requirement.cloud_spec.compute_profile.sha256,
            freeze_event_id=requirement.freeze_event.event_id,
            freeze_event_hash=requirement.freeze_event.event_hash,
            freeze_event_index=requirement.freeze_event_index,
            escalation_event_id=requirement.escalation_event.event_id,
            escalation_event_hash=requirement.escalation_event.event_hash,
            escalation_event_index=requirement.escalation_event_index,
            source_artifact_sha256s=tuple(record.sha256 for record in sources.records),
            source_artifact_record_hashes=tuple(str(record.record_hash) for record in sources.records),
            ledger_event_id=event.event_id,
            ledger_event_hash=event.event_hash,
            ledger_event_index=event_index,
            ledger_prefix_head_hash=event.event_hash,
        )
    observation = sources.observation
    state = observation.runtime_state
    records = sources.records
    if event.event_hash is None:
        raise ComputeTerminalError("compute terminal event hash is absent")
    if observation.ledger_event_index >= event_index:
        raise ComputeTerminalError(
            "compute terminal assessment must follow its wall observation"
        )
    return ComputeTerminalAssessment(
        assessment_id=assessment_id,
        ledger_run_id=sources.freeze.run_id,
        execution_run_id=sources.spec.run_id,
        scientific_binding_sha256=sources.spec.scientific_binding_sha256,
        evaluation_contract_freeze_receipt_artifact_sha256=sources.freeze_record.sha256,
        evaluation_contract_freeze_receipt_record_hash=str(
            sources.freeze_record.record_hash
        ),
        contract_artifact_sha256=sources.contract_record.sha256,
        contract_record_hash=str(sources.contract_record.record_hash),
        frozen_run_spec_artifact_sha256=sources.spec_record.sha256,
        frozen_run_spec_record_hash=str(sources.spec_record.record_hash),
        frozen_configuration_inventory_artifact_sha256=(
            sources.inventory_record.sha256
        ),
        frozen_configuration_inventory_record_hash=str(
            sources.inventory_record.record_hash
        ),
        wall_budget_observation_artifact_sha256=sources.observation_record.sha256,
        wall_budget_observation_record_hash=str(
            sources.observation_record.record_hash
        ),
        resource_config=observation.resource_config,
        resource_config_sha256=resource_config_sha256(
            observation.resource_config
        ),
        external_resource_authority_sequence=(
            observation.external_authority_sequence
        ),
        external_resource_authority_sha256=observation.external_authority_sha256,
        maximum_wall_clock_seconds=(
            observation.resource_config.maximum_wall_clock_seconds
        ),
        wall_started_at_epoch_seconds=state.wall_started_at_epoch_seconds,
        wall_observed_at_epoch_seconds=state.wall_observed_at_epoch_seconds,
        wall_elapsed_seconds=state.wall_elapsed_seconds,
        mandatory_work_status=MANDATORY_WORK_STATUS,
        external_effect_status=EXTERNAL_EFFECT_STATUS,
        factual_status=WALL_BUDGET_EXHAUSTED_STATUS,
        source_artifact_sha256s=tuple(record.sha256 for record in records),
        source_artifact_record_hashes=tuple(
            str(record.record_hash) for record in records
        ),
        ledger_event_id=event.event_id,
        ledger_event_hash=event.event_hash,
        ledger_event_index=event_index,
        ledger_prefix_head_hash=event.event_hash,
    )


def _matching_assessment_events(
    events: tuple[LedgerEvent, ...],
    *,
    assessment_id: str,
    scientific_binding_sha256: str,
) -> tuple[tuple[int, LedgerEvent, Mapping[str, Any]], ...]:
    matches: list[tuple[int, LedgerEvent, Mapping[str, Any]]] = []
    for index, event in enumerate(events):
        binding = event.metadata.get(COMPUTE_TERMINAL_EVENT_KEY)
        if binding is None:
            continue
        if not isinstance(binding, Mapping):
            raise ComputeTerminalError("compute terminal event binding is malformed")
        if (
            binding.get("assessment_id") == assessment_id
            or binding.get("scientific_binding_sha256") == scientific_binding_sha256
        ):
            matches.append((index, event, binding))
    return tuple(matches)


def _compute_assessment_event_id(binding: Mapping[str, Any]) -> str:
    return "compute-terminal-" + hashlib.sha256(
        canonical_json_bytes(binding)
    ).hexdigest()[:24]


def _matching_publication_events(
    events: tuple[LedgerEvent, ...],
    *,
    assessment_id: str,
    sources: _ComputeSources | _GpuComputeSources,
) -> tuple[tuple[int, LedgerEvent, Mapping[str, Any]], ...]:
    if type(sources) is _ComputeSources:
        return _matching_assessment_events(
            events, assessment_id=assessment_id,
            scientific_binding_sha256=sources.spec.scientific_binding_sha256,
        )
    if type(sources) is not _GpuComputeSources:
        raise ComputeTerminalError("unknown compute publication source family")
    requirement = sources.requirement
    matches = []
    for index, event in enumerate(events):
        binding = event.metadata.get(COMPUTE_TERMINAL_EVENT_KEY)
        if binding is None:
            continue
        if not isinstance(binding, Mapping):
            raise ComputeTerminalError("compute terminal event binding is malformed")
        if (binding.get("assessment_id") == assessment_id
                or binding.get("scientific_binding_sha256") == sources.spec.scientific_binding_sha256
                or binding.get("project_definition_sha256") == requirement.project_definition_sha256
                or thaw_json(binding.get("obligation_identity")) == list(requirement.obligation_identity)):
            matches.append((index, event, binding))
    return tuple(matches)


def _validate_gpu_compute_assessment_event(
    event: LedgerEvent,
    event_index: int,
    events: tuple[LedgerEvent, ...],
    *,
    binding: Mapping[str, Any],
    sources: _GpuComputeSources,
) -> None:
    requirement = sources.requirement
    if not 0 < event_index < len(events):
        raise ComputeTerminalError("GPU compute event index is invalid")
    prior = events[event_index - 1]
    if (event.event_hash is None
            or events[event_index] != event
            or event.event_id != _compute_assessment_event_id(binding)
            or event.run_id != requirement.freeze.run_id
            or event.actor_role is not Role.CLAIM_VERIFIER
            or event.event_type != "CHECKPOINT"
            or not isinstance(event.state_before, MacroState)
            or event.state_before != event.requested_state_after
            or event.state_before != prior.requested_state_after
            or event.prior_event_hash != prior.event_hash
            or event.artifact_hashes != tuple(record.sha256 for record in sources.records)
            or event.code_version != prior.code_version
            or event.configuration_hash != prior.configuration_hash
            or bool(event.dataset_identifiers) or bool(event.evaluator_outputs)
            or event.random_seeds != sources.spec.seeds
            or thaw_json(event.metadata) != {COMPUTE_TERMINAL_EVENT_KEY: dict(binding)}
            or event.reason != _GPU_ASSESSMENT_REASON
            or requirement.freeze_event_index >= event_index
            or requirement.escalation_event_index >= event_index
            or any(isinstance(item.state_before, TerminalState)
                   or isinstance(item.requested_state_after, TerminalState) for item in events)
            or any(item.event_type == "CORRECTION" and item.supersedes_event_id == event.event_id
                   for item in events[event_index + 1:])):
        raise ComputeTerminalError("GPU compute event is stale, substituted or nonprospective")


def _validate_compute_assessment_event(
    event: LedgerEvent,
    event_index: int,
    events: tuple[LedgerEvent, ...],
    *,
    binding: Mapping[str, Any],
    sources: _ComputeSources | _GpuComputeSources,
) -> None:
    if type(sources) is _GpuComputeSources:
        _validate_gpu_compute_assessment_event(
            event, event_index, events, binding=binding, sources=sources,
        )
        return
    if event_index <= 0 or event_index >= len(events):
        raise ComputeTerminalError("compute terminal assessment event index is invalid")
    prior = events[event_index - 1]
    invalid = (
        event.event_hash is None
        or event.event_id != _compute_assessment_event_id(binding)
        or event.actor_role is not Role.CLAIM_VERIFIER
        or event.event_type != "CHECKPOINT"
        or not isinstance(event.state_before, MacroState)
        or event.state_before != event.requested_state_after
        or any(
            isinstance(candidate.state_before, TerminalState)
            or isinstance(candidate.requested_state_after, TerminalState)
            for candidate in events[: event_index + 1]
        )
        or event.state_before != prior.requested_state_after
        or event.prior_event_hash != prior.event_hash
        or event.artifact_hashes
        != tuple(record.sha256 for record in sources.records)
        or event.code_version != prior.code_version
        or event.configuration_hash != prior.configuration_hash
        or bool(event.dataset_identifiers)
        or event.random_seeds != sources.spec.seeds
        or bool(event.evaluator_outputs)
        or thaw_json(event.metadata) != {COMPUTE_TERMINAL_EVENT_KEY: dict(binding)}
        or event.reason
        != "verified never-started mandatory work after run wall-budget exhaustion"
        or _utc_epoch_seconds(event.timestamp, "compute terminal assessment")
        < sources.observation.runtime_state.wall_observed_at_epoch_seconds
        or sources.observation.ledger_event_index >= event_index
        or any(
            later.event_type == "CORRECTION"
            and later.supersedes_event_id == event.event_id
            for later in events[event_index + 1 :]
        )
    )
    if invalid:
        raise ComputeTerminalError(
            "compute terminal assessment event is stale or substituted"
        )


def register_compute_terminal_assessment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    assessment_id: str,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    evaluation_contract_freeze_receipt_artifact_sha256: str,
    frozen_configuration_inventory_artifact_sha256: str,
    wall_budget_observation_artifact_sha256: str,
) -> ArtifactRecord:
    validate_identifier(assessment_id, "compute terminal assessment ID")
    with _project_resource_execution_lock(registry.policy.root):
        status, reason, sources = _derive_sources(
            registry,
            ledger,
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
            evaluation_contract_freeze_receipt_artifact_sha256=(
                evaluation_contract_freeze_receipt_artifact_sha256
            ),
            frozen_configuration_inventory_artifact_sha256=(
                frozen_configuration_inventory_artifact_sha256
            ),
            wall_budget_observation_artifact_sha256=(
                wall_budget_observation_artifact_sha256
            ),
        )
        if status is not ComputeTerminalAssessmentResolutionStatus.AUTHORIZED or sources is None:
            raise ComputeTerminalError(f"compute terminal assessment is not authorized: {reason}")
        record = _publish_verified_compute_assessment(
            registry, ledger, assessment_id=assessment_id,
            expected_ledger_run_id=expected_ledger_run_id, sources=sources,
        )
        _require_compute_terminal_assessment(
            registry,
            ledger,
            assessment_artifact_sha256=record.sha256,
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
            project_lock_held=True,
        )
        return record


def _publish_verified_compute_assessment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    assessment_id: str,
    expected_ledger_run_id: str,
    sources: _ComputeSources | _GpuComputeSources,
) -> ArtifactRecord:
    """Publish the existing compute family under the caller's project lock.

    Source replay precedes entry; the same paired source snapshot must still
    hold at publication. The caller performs full owner readback afterward.
    This shared path owns capacity, event-first recovery and the exact delta.
    """
    if type(sources) not in {_ComputeSources, _GpuComputeSources}:
        raise ComputeTerminalError("unknown compute publication source family")
    gpu = type(sources) is _GpuComputeSources
    origin = GPU_COMPUTE_TERMINAL_ASSESSMENT_ORIGIN if gpu else COMPUTE_TERMINAL_ASSESSMENT_ORIGIN
    record_schema = "2.0" if gpu else "1.0"
    event_reason = _GPU_ASSESSMENT_REASON if gpu else "verified never-started mandatory work after run wall-budget exhaustion"
    binding = _assessment_event_binding(assessment_id, sources)
    registry.verify_all(raise_on_error=True)
    ledger.assert_valid()
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            locked_registry = registry._verify_all_locked(
                registry_guard, raise_on_error=True
            )
            locked_ledger = ledger._validate_bytes(
                ledger._read_raw_locked(ledger_guard)
            )
            if (
                not locked_ledger.valid
                or locked_registry != sources.registry_snapshot
                or locked_ledger != sources.ledger_snapshot
            ):
                raise ComputeTerminalError(
                    "compute terminal sources changed before admission"
                )
            matches = _matching_publication_events(
                locked_ledger.events,
                assessment_id=assessment_id,
                sources=sources,
            )
            if len(matches) > 1:
                raise ComputeTerminalError(
                    "compute terminal assessment slot is ambiguous"
                )

            def build(snapshot: Any) -> LedgerEvent:
                if snapshot != locked_ledger or not snapshot.events:
                    raise ComputeTerminalError(
                        "compute terminal ledger changed before admission"
                    )
                state = snapshot.events[-1].requested_state_after
                if not isinstance(state, MacroState):
                    raise ComputeTerminalError(
                        "compute terminal assessment cannot follow a terminal state"
                    )
                return LedgerEvent.create(
                    run_id=expected_ledger_run_id,
                    event_id=_compute_assessment_event_id(binding),
                    timestamp=admission_timestamp,
                    actor_role=Role.CLAIM_VERIFIER,
                    state_before=state,
                    requested_state_after=state,
                    artifact_hashes=tuple(
                        record.sha256 for record in sources.records
                    ),
                    code_version=snapshot.events[-1].code_version,
                    configuration_hash=snapshot.events[-1].configuration_hash,
                    dataset_identifiers=(),
                    random_seeds=sources.spec.seeds,
                    evaluator_outputs=(),
                    reason=event_reason,
                    prior_event_hash=snapshot.head_hash,
                    event_type="CHECKPOINT",
                    metadata={COMPUTE_TERMINAL_EVENT_KEY: binding},
                )

            if matches:
                event_index, event, admitted = matches[0]
                if thaw_json(admitted) != binding:
                    raise ComputeTerminalError(
                        "compute terminal assessment slot is competing"
                    )
                _validate_compute_assessment_event(
                    event,
                    event_index,
                    locked_ledger.events,
                    binding=binding,
                    sources=sources,
                )
                committed_ledger = locked_ledger
            else:
                admission_timestamp = utc_now()
                event = build(locked_ledger)
                event_index = locked_ledger.event_count

            assessment = _assessment_from_event(
                assessment_id,
                sources,
                event,
                event_index,
            )
            data = canonical_json_bytes(assessment.to_dict()) + b"\n"
            if len(data) > _MAX_COMPUTE_TERMINAL_BYTES:
                raise ComputeTerminalError(
                    "compute terminal assessment exceeds byte bound"
                )
            prospective_sha256 = hashlib.sha256(data).hexdigest()
            existing_record = next(
                (
                    item
                    for item in locked_registry.records
                    if item.sha256 == prospective_sha256
                ),
                None,
            )
            parents = assessment.source_artifact_sha256s
            if existing_record is not None and not registry._semantic_match(
                existing_record,
                logical_type=COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE,
                schema_version=record_schema,
                mime_type="application/json",
                origin=origin,
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=COMPUTE_TERMINAL_ASSESSMENT_COMMAND,
                parents=parents,
                validation_result="PASS",
                frozen=True,
            ):
                raise ComputeTerminalError(
                    "compute terminal assessment registry slot is competing"
                )
            if gpu and existing_record is not None and existing_record.created_at != event.timestamp:
                raise ComputeTerminalError("GPU compute assessment timestamp slot is competing")
            publications = tuple(
                item
                for item in locked_registry.records
                if item.logical_type
                == COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE
                and item.parent_artifacts == parents
            )
            if len(publications) > 1 or (
                publications
                and publications[0].sha256 != prospective_sha256
            ):
                raise ComputeTerminalError(
                    "compute terminal assessment publication is competing"
                )
            records_needed = int(existing_record is None)
            events_needed = int(not matches)
            if locked_registry.count + records_needed > MAX_REGISTRY_RECORDS:
                raise ComputeTerminalError(
                    "compute terminal registry capacity is insufficient"
                )
            if locked_ledger.event_count + events_needed > MAX_LEDGER_EVENTS:
                raise ComputeTerminalError(
                    "compute terminal ledger capacity is insufficient"
                )
            if not matches:
                line = canonical_json_bytes(event.to_dict()) + b"\n"
                if (
                    len(line) > _MAX_COMPUTE_TERMINAL_BYTES
                    or locked_ledger.valid_prefix_bytes + len(line)
                    > MAX_LEDGER_BYTES
                ):
                    raise ComputeTerminalError(
                        "compute terminal ledger byte capacity is insufficient"
                    )
                appended = ledger._append_locked(ledger_guard, build)
                if appended != event:
                    raise ComputeTerminalError(
                        "compute terminal event append changed identity"
                    )
                committed_ledger = ledger._validate_bytes(
                    ledger._read_raw_locked(ledger_guard)
                )
                if not committed_ledger.valid:
                    raise ComputeTerminalError(
                        "compute terminal event append did not verify"
                    )
                _validate_compute_assessment_event(
                    appended,
                    event_index,
                    committed_ledger.events,
                    binding=binding,
                    sources=sources,
                )
            record = registry._put_bytes_locked(
                registry_guard,
                data,
                logical_type=COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE,
                origin=origin,
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=COMPUTE_TERMINAL_ASSESSMENT_COMMAND,
                parent_artifacts=parents,
                schema_version=record_schema,
                mime_type="application/json",
                validation_result="PASS",
                frozen=True,
                created_at=event.timestamp if gpu else None,
            )
            final_registry = registry._verify_all_locked(
                registry_guard,
                raise_on_error=True,
            )
            final_ledger = ledger._validate_bytes(
                ledger._read_raw_locked(ledger_guard)
            )
            expected_records = {item.sha256: item for item in locked_registry.records}
            expected_records[record.sha256] = record
            if (
                final_registry.count
                != locked_registry.count + records_needed
                or {item.sha256: item for item in final_registry.records} != expected_records
                or final_ledger != committed_ledger
                or record.sha256 != prospective_sha256
            ):
                raise ComputeTerminalError(
                    "compute terminal admission changed outside its exact delta"
                )
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    return record


def _require_compute_terminal_assessment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    assessment_artifact_sha256: str,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    project_lock_held: bool,
) -> ComputeTerminalAssessment | GpuRequirementComputeTerminalAssessment:
    def replay() -> ComputeTerminalAssessment | GpuRequirementComputeTerminalAssessment:
        entry_registry, entry_ledger = _locked_resource_registry_ledger_snapshot(
            registry, ledger, expected_ledger_run_id
        )
        record, value = _load_json_record(
            registry,
            assessment_artifact_sha256,
            logical_type=COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE,
            creator_role=Role.CLAIM_VERIFIER,
        )
        if value.get("schema_version") == GPU_COMPUTE_TERMINAL_ASSESSMENT_SCHEMA:
            assessment = _require_gpu_compute_terminal_assessment(
                registry, ledger,
                assessment_artifact_sha256=assessment_artifact_sha256,
                expected_ledger_run_id=expected_ledger_run_id,
                expected_execution_run_id=expected_execution_run_id,
                project_lock_held=True,
            )
            if _locked_resource_registry_ledger_snapshot(
                registry, ledger, expected_ledger_run_id,
            ) != (entry_registry, entry_ledger):
                raise ComputeTerminalError("compute source selector changed during GPU replay")
            return assessment
        if (
            record.origin != COMPUTE_TERMINAL_ASSESSMENT_ORIGIN
            or record.creation_command != COMPUTE_TERMINAL_ASSESSMENT_COMMAND
        ):
            raise ComputeTerminalError("compute terminal assessment is not source-owned")
        assessment = ComputeTerminalAssessment.from_mapping(value)
        if (
            assessment.ledger_run_id != expected_ledger_run_id
            or assessment.execution_run_id != expected_execution_run_id
            or record.parent_artifacts != assessment.source_artifact_sha256s
        ):
            raise ComputeTerminalError("compute terminal assessment names another closure")
        status, reason, sources = _derive_sources(
            registry,
            ledger,
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
            evaluation_contract_freeze_receipt_artifact_sha256=(
                assessment.evaluation_contract_freeze_receipt_artifact_sha256
            ),
            frozen_configuration_inventory_artifact_sha256=(
                assessment.frozen_configuration_inventory_artifact_sha256
            ),
            wall_budget_observation_artifact_sha256=(
                assessment.wall_budget_observation_artifact_sha256
            ),
        )
        if status is not ComputeTerminalAssessmentResolutionStatus.AUTHORIZED or sources is None:
            raise ComputeTerminalError(
                f"compute terminal assessment is no longer authorized: {reason}"
            )
        matches = _matching_assessment_events(
            entry_ledger.events,
            assessment_id=assessment.assessment_id,
            scientific_binding_sha256=assessment.scientific_binding_sha256,
        )
        if len(matches) != 1:
            raise ComputeTerminalError("compute terminal assessment event is ambiguous")
        event_index, event, binding = matches[0]
        _validate_compute_assessment_event(
            event,
            event_index,
            entry_ledger.events,
            binding=_assessment_event_binding(assessment.assessment_id, sources),
            sources=sources,
        )
        stale_reasons = tuple(
            label
            for label, invalid in (
                (
                    "binding",
                    thaw_json(binding)
                    != _assessment_event_binding(assessment.assessment_id, sources),
                ),
                ("event_hash", event.event_hash is None),
                ("actor", event.actor_role is not Role.CLAIM_VERIFIER),
                ("event_type", event.event_type != "CHECKPOINT"),
                (
                    "terminal_prefix",
                    any(
                        isinstance(candidate.state_before, TerminalState)
                        or isinstance(
                            candidate.requested_state_after,
                            TerminalState,
                        )
                        for candidate in entry_ledger.events[: event_index + 1]
                    ),
                ),
                ("state", event.state_before != event.requested_state_after),
                (
                    "prior_state",
                    event_index == 0
                    or event.state_before
                    != entry_ledger.events[event_index - 1].requested_state_after,
                ),
                (
                    "prior_hash",
                    event_index == 0
                    or event.prior_event_hash
                    != entry_ledger.events[event_index - 1].event_hash,
                ),
                (
                    "artifacts",
                    event.artifact_hashes
                    != tuple(source.sha256 for source in sources.records),
                ),
                ("seeds", event.random_seeds != sources.spec.seeds),
                ("datasets", bool(event.dataset_identifiers)),
                ("evaluators", bool(event.evaluator_outputs)),
                (
                    "metadata",
                    thaw_json(event.metadata)
                    != {
                        COMPUTE_TERMINAL_EVENT_KEY: _assessment_event_binding(
                            assessment.assessment_id, sources
                        )
                    },
                ),
                (
                    "reason",
                    event.reason
                    != "verified never-started mandatory work after run wall-budget exhaustion",
                ),
                (
                    "correction",
                    any(
                later.event_type == "CORRECTION"
                and later.supersedes_event_id == event.event_id
                for later in entry_ledger.events[event_index + 1 :]
                    ),
                ),
            )
            if invalid
        )
        if stale_reasons:
            raise ComputeTerminalError(
                "compute terminal assessment event is stale or substituted: "
                + ",".join(stale_reasons)
            )
        expected = _assessment_from_event(
            assessment.assessment_id, sources, event, event_index
        )
        if assessment != expected:
            raise ComputeTerminalError("compute terminal assessment differs from source replay")
        publications = tuple(
            item
            for item in registry.list_records()
            if item.logical_type == COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE
            and item.parent_artifacts == assessment.source_artifact_sha256s
        )
        if publications != (record,):
            raise ComputeTerminalError("compute terminal assessment publication is ambiguous")
        final_registry, final_ledger = _locked_resource_registry_ledger_snapshot(
            registry, ledger, expected_ledger_run_id
        )
        if final_registry != entry_registry or final_ledger != entry_ledger:
            raise ComputeTerminalError(
                "compute terminal assessment sources changed during replay"
            )
        return assessment

    if project_lock_held:
        return replay()
    with _project_resource_execution_lock(registry.policy.root):
        return replay()


def require_compute_terminal_assessment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    assessment_artifact_sha256: str,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
) -> ComputeTerminalAssessment | GpuRequirementComputeTerminalAssessment:
    return _require_compute_terminal_assessment(
        registry,
        ledger,
        assessment_artifact_sha256=assessment_artifact_sha256,
        expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_execution_run_id,
        project_lock_held=False,
    )


def _derive_gpu_compute_sources(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    evaluation_contract_freeze_receipt_artifact_sha256: str,
    compute_escalation_plan_authority_artifact_sha256: str,
) -> _GpuComputeSources:
    from .gpu_validation_requirement import (
        GpuValidationRequirementStatus,
        _resolve_gpu_validation_requirement,
    )

    resolution = _resolve_gpu_validation_requirement(
        registry, ledger, expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_execution_run_id,
        evaluation_contract_freeze_receipt_artifact_sha256=evaluation_contract_freeze_receipt_artifact_sha256,
        compute_escalation_plan_authority_artifact_sha256=compute_escalation_plan_authority_artifact_sha256,
        project_lock_held=True,
    )
    if (resolution.status is not GpuValidationRequirementStatus.REQUIREMENT_ESTABLISHED
            or resolution.requirement is None):
        raise ComputeTerminalError(f"GPU protocol requirement is unavailable: {resolution.reason_code}")
    sources = _GpuComputeSources(resolution.requirement)
    if (not sources.ledger_snapshot.events
            or any(isinstance(event.state_before, TerminalState)
                   or isinstance(event.requested_state_after, TerminalState)
                   for event in sources.ledger_snapshot.events)):
        raise ComputeTerminalError("prior terminal cause precludes a new GPU compute assessment")
    if len(sources.records) > 255:
        raise ComputeTerminalError("GPU compute source closure leaves no terminal evidence slot")
    return sources


def register_gpu_requirement_compute_terminal_assessment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    assessment_id: str,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    evaluation_contract_freeze_receipt_artifact_sha256: str,
    compute_escalation_plan_authority_artifact_sha256: str,
) -> ArtifactRecord:
    """Register only the full-owned unperformed device-protocol requirement.

    This permits an operational terminal fact, never scientific promotion,
    source/binary equivalence, a GPU job or resource-spending authority.
    """
    if type(assessment_id) is not str:
        raise ComputeTerminalError("GPU compute assessment ID must be native text")
    validate_identifier(assessment_id, "GPU compute assessment ID")
    with _project_resource_execution_lock(registry.policy.root):
        sources = _derive_gpu_compute_sources(
            registry, ledger, expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id,
            evaluation_contract_freeze_receipt_artifact_sha256=evaluation_contract_freeze_receipt_artifact_sha256,
            compute_escalation_plan_authority_artifact_sha256=compute_escalation_plan_authority_artifact_sha256,
        )
        record = _publish_verified_compute_assessment(
            registry, ledger, assessment_id=assessment_id,
            expected_ledger_run_id=expected_ledger_run_id, sources=sources,
        )
        _require_compute_terminal_assessment(
            registry, ledger, assessment_artifact_sha256=record.sha256,
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=expected_execution_run_id, project_lock_held=True,
        )
        return record


def _require_gpu_compute_terminal_assessment(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    assessment_artifact_sha256: str,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    project_lock_held: bool,
) -> GpuRequirementComputeTerminalAssessment:
    if not project_lock_held:
        with _project_resource_execution_lock(registry.policy.root):
            return _require_gpu_compute_terminal_assessment(
                registry, ledger, assessment_artifact_sha256=assessment_artifact_sha256,
                expected_ledger_run_id=expected_ledger_run_id,
                expected_execution_run_id=expected_execution_run_id, project_lock_held=True,
            )
    entry = _locked_resource_registry_ledger_snapshot(registry, ledger, expected_ledger_run_id)
    record, value = _load_json_record(
        registry, assessment_artifact_sha256,
        logical_type=COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE, creator_role=Role.CLAIM_VERIFIER,
    )
    assessment = GpuRequirementComputeTerminalAssessment.from_mapping(value)
    if (record.schema_version != "2.0" or record.mime_type != "application/json"
            or record.origin != GPU_COMPUTE_TERMINAL_ASSESSMENT_ORIGIN
            or record.creation_command != COMPUTE_TERMINAL_ASSESSMENT_COMMAND
            or record.size > _MAX_COMPUTE_TERMINAL_BYTES
            or assessment.ledger_run_id != expected_ledger_run_id
            or assessment.execution_run_id != expected_execution_run_id
            or record.parent_artifacts != assessment.source_artifact_sha256s):
        raise ComputeTerminalError("GPU compute assessment source metadata or closure differs")
    sources = _derive_gpu_compute_sources(
        registry, ledger, expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_execution_run_id,
        evaluation_contract_freeze_receipt_artifact_sha256=assessment.evaluation_contract_freeze_receipt_artifact_sha256,
        compute_escalation_plan_authority_artifact_sha256=assessment.compute_escalation_plan_authority_artifact_sha256,
    )
    if (sources.registry_snapshot, sources.ledger_snapshot) != entry:
        raise ComputeTerminalError("GPU compute sources changed before full event replay")
    matches = _matching_publication_events(
        entry[1].events, assessment_id=assessment.assessment_id, sources=sources,
    )
    if len(matches) != 1:
        raise ComputeTerminalError("GPU compute assessment event slot is ambiguous")
    index, event, binding = matches[0]
    expected_binding = _assessment_event_binding(assessment.assessment_id, sources)
    if thaw_json(binding) != expected_binding:
        raise ComputeTerminalError("GPU compute event differs from full source replay")
    _validate_compute_assessment_event(
        event, index, entry[1].events, binding=expected_binding, sources=sources,
    )
    if (assessment != _assessment_from_event(assessment.assessment_id, sources, event, index)
            or record.created_at != event.timestamp):
        raise ComputeTerminalError("GPU compute assessment differs from its owned event")
    publications = tuple(item for item in entry[0].records
                         if item.logical_type == COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE
                         and item.parent_artifacts == assessment.source_artifact_sha256s)
    if publications != (record,):
        raise ComputeTerminalError("GPU compute assessment publication is ambiguous")
    if _locked_resource_registry_ledger_snapshot(registry, ledger, expected_ledger_run_id) != entry:
        raise ComputeTerminalError("GPU compute sources changed during complete readback")
    return assessment


__all__ = [
    "COMPUTE_TERMINAL_ASSESSMENT_LOGICAL_TYPE",
    "COMPUTE_TERMINAL_ASSESSMENT_SCHEMA",
    "COMPUTE_TERMINAL_AUTHORITY_SCOPE",
    "ComputeTerminalAssessment",
    "ComputeTerminalAssessmentResolution",
    "ComputeTerminalAssessmentResolutionStatus",
    "ComputeTerminalError",
    "GPU_COMPUTE_TERMINAL_ASSESSMENT_SCHEMA",
    "GPU_COMPUTE_TERMINAL_ASSESSMENT_ORIGIN",
    "GPU_PROTOCOL_REQUIRED_STATUS",
    "GPU_REQUIREMENT_SCOPE",
    "GpuRequirementComputeTerminalAssessment",
    "EXTERNAL_EFFECT_STATUS",
    "MANDATORY_WORK_STATUS",
    "WALL_BUDGET_EXHAUSTED_STATUS",
    "register_compute_terminal_assessment",
    "register_gpu_requirement_compute_terminal_assessment",
    "require_compute_terminal_assessment",
    "resolve_compute_terminal_assessment",
]
