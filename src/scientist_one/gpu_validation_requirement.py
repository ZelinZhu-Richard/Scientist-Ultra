"""Nonissuing ownership of one never-started, device-scoped CUDA requirement.

The retained protocol measures CUDA-event time, not interchangeable CPU/MPS
time.  This owner establishes only that the admitted LOCAL_MAC grammar cannot
supply that quantity.  It does not establish physical CPU incapacity, available
GPU capacity, source/binary equivalence, execution, scientific adequacy, or
permission to spend.  No Result, inference, or terminal authority is issued.

Progress selection is intentionally more conservative than scientific identity:
the same four input hashes also prevent a never-started result
after IDs/profiles/attempts are renamed.  This can refuse a different contract
reusing identical work; it never grants cross-contract scientific evidence.
The configuration bytes already freeze the protocol's full ordered seed tuple;
an inconsistent declared spec seed subset cannot erase progress on those bytes.
Unclassifiable progress is unavailable evidence, not evidence of no progress.
Only a fully replayed unrelated preparation can exclude its exact owned
records/event. Other unrelated partial or output lifecycles remain unavailable
in this narrow profile. This is a retained registry/ledger boundary, not a
measurement of unrecorded machine activity or total study completion.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Mapping

from .artifacts import (
    MAX_ARTIFACT_PARENTS,
    MAX_REGISTRY_RECORDS,
    ArtifactRecord,
    ArtifactRegistry,
    RegistryValidationResult,
)
from .cuda_device_timing import (
    CUDA_DEVICE_TIMING_BENCHMARK_BYTES,
    CUDA_DEVICE_TIMING_EVALUATOR_BYTES,
    CUDA_DEVICE_TIMING_METRIC_AGGREGATION,
    CUDA_DEVICE_TIMING_METRIC_DEFINITION,
    CUDA_DEVICE_TIMING_PROFILE_ID,
    CudaDeviceTimingProtocol,
    validate_cuda_device_timing_dataset,
)
from .errors import ArtifactError, LedgerError, ValidationError
from .experiments import (
    COMPUTE_ESCALATION_CLOUD_SPEC_LOGICAL_TYPE,
    COMPUTE_ESCALATION_LOCAL_SPEC_LOGICAL_TYPE,
    AcceleratorKind,
    ComputeEscalationBudget,
    ComputeEscalationPlanAuthority,
    ComputeMode,
    EscalationDecision,
    EvidenceClass,
    ExperimentError,
    FrozenRunSpec,
    GPUCloudSubmissionPlan,
    ValidationStatus,
    _load_compute_escalation_input,
    _parse_escalation_budget,
    _parse_escalation_decision,
    _parse_frozen_run_spec,
    _parse_human_gate_policy,
    _parse_submission_plan,
    _require_scientific_execution_spec_and_inputs,
    require_compute_escalation_plan_authority,
    require_scientific_execution_preparation,
)
from .ledger import EventLedger, LedgerEvent, LedgerValidationResult
from .models import thaw_json, validate_identifier, validate_sha256
from .orchestrator import (
    OrchestrationError,
    _locked_resource_registry_ledger_snapshot,
    _project_resource_execution_lock,
)
from .roles import Role
from .scientific_design import (
    BaselineStatus,
    EvaluationContract,
    EvaluationContractFreezeGateReceipt,
    ExperimentPlan,
    MetricDirection,
    MetricScope,
    MetricUnit,
    ScientificDesignError,
    require_evaluation_contract_freeze_gate_receipt,
    require_frozen_evaluation_contract,
)
from .security import canonical_json_bytes, safe_json_loads

if TYPE_CHECKING:
    from .gates import HumanGatePolicy


GPU_VALIDATION_REQUIREMENT_POLICY_METADATA_KEY = "gpu_validation_requirement_policy"
GPU_VALIDATION_REQUIREMENT_POLICY_SCHEMA = "gpu-validation-requirement-policy/v1"
GPU_VALIDATION_REQUIREMENT_SCOPE = "ONE_MANDATORY_CUDA_DEVICE_TIMING_OBLIGATION"

_SPEC_TYPES = frozenset({
    "frozen_run_spec", "autonomous_implementation.frozen_run_spec",
    "gpu_cloud_source_run_spec", "gpu_cloud_target_run_spec",
    COMPUTE_ESCALATION_LOCAL_SPEC_LOGICAL_TYPE,
    COMPUTE_ESCALATION_CLOUD_SPEC_LOGICAL_TYPE,
})
_PROGRESS_TYPES = frozenset({
    "operational_seed_admission", "local_terminal_observation",
    "operational_best_of_n_report",
    "adaptive_execution_plan", "adaptive_execution_plan_binding",
    "execution_input_binding", "execution_environment", "run_manifest",
    "backend_execution_attestation", "experiment_output_manifest",
    "autonomous_implementation.execution_receipt",
    "compute_escalation_submission_authorization",
})
_PROGRESS_PREFIXES = (
    "scientific_execution_", "experiment_output.", "experiment_output_",
    "gpu_cloud_", "scheduled_gpu_",
)
_MAX_SELECTOR_BYTES = 8 * 1024 * 1024


class GpuValidationRequirementError(ValidationError):
    """The requested source boundary cannot be evaluated exactly."""


class GpuValidationRequirementStatus(StrEnum):
    REQUIREMENT_ESTABLISHED = "REQUIREMENT_ESTABLISHED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    WORK_ALREADY_STARTED = "WORK_ALREADY_STARTED"
    BLOCKED_LOCAL = "BLOCKED_LOCAL"
    BLOCKED_EXTERNAL = "BLOCKED_EXTERNAL"


@dataclass(frozen=True, slots=True)
class GpuValidationRequirement:
    """Ephemeral full-owner result, never a caller-admissible authority DTO."""

    freeze_record: ArtifactRecord
    freeze: EvaluationContractFreezeGateReceipt
    contract_record: ArtifactRecord
    contract: EvaluationContract
    plan_records: tuple[ArtifactRecord, ...]
    plans: tuple[ExperimentPlan, ...]
    local_spec_record: ArtifactRecord
    local_spec: FrozenRunSpec
    cloud_spec: FrozenRunSpec
    escalation_record: ArtifactRecord
    escalation: ComputeEscalationPlanAuthority
    escalation_input_records: tuple[ArtifactRecord, ...]
    decision: EscalationDecision
    submission_plan: GPUCloudSubmissionPlan
    budget: ComputeEscalationBudget
    human_gate_policy: HumanGatePolicy
    protocol: CudaDeviceTimingProtocol
    input_records: tuple[ArtifactRecord, ...]
    input_bytes: tuple[bytes, ...]
    source_records: tuple[ArtifactRecord, ...]
    entry_registry_snapshot: RegistryValidationResult
    entry_ledger_snapshot: LedgerValidationResult
    freeze_event: LedgerEvent
    escalation_event: LedgerEvent

    @property
    def project_definition_sha256(self) -> str:
        return self.local_spec.project_definition_sha256

    @property
    def obligation_identity(self) -> tuple[str, str, str, str]:
        return (self.contract_record.sha256, self.contract.sha256,
                self.local_spec.hypothesis_id, self.local_spec.experiment_id)

    @property
    def freeze_event_index(self) -> int:
        return self.freeze.design_freeze_event_index

    @property
    def escalation_event_index(self) -> int:
        return self.escalation.ledger_event_index

    @property
    def scope(self) -> str:
        return GPU_VALIDATION_REQUIREMENT_SCOPE

    @property
    def external_validation(self) -> ValidationStatus:
        return ValidationStatus.UNTESTED

    @property
    def scientific_evidence_eligible(self) -> bool:
        return False

    @property
    def spending_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class GpuValidationRequirementResolution:
    status: GpuValidationRequirementStatus
    reason_code: str
    requirement: GpuValidationRequirement | None = None

    def __post_init__(self) -> None:
        if (type(self) is not GpuValidationRequirementResolution
                or type(self.status) is not GpuValidationRequirementStatus
                or type(self.reason_code) is not str):
            raise GpuValidationRequirementError("resolution requires exact native values")
        validate_identifier(self.reason_code, "GPU requirement reason")
        if ((self.status is GpuValidationRequirementStatus.REQUIREMENT_ESTABLISHED)
                != (type(self.requirement) is GpuValidationRequirement)):
            raise GpuValidationRequirementError("resolution status and owned sources differ")
        if (self.status is not GpuValidationRequirementStatus.REQUIREMENT_ESTABLISHED
                and self.requirement is not None):
            raise GpuValidationRequirementError("unavailable requirement cannot retain success")


def _unavailable(status: GpuValidationRequirementStatus,
                 reason: str) -> GpuValidationRequirementResolution:
    return GpuValidationRequirementResolution(status, reason)


def _mapping(registry: ArtifactRegistry, record: ArtifactRecord) -> Mapping[str, Any]:
    if record.size > _MAX_SELECTOR_BYTES:
        raise GpuValidationRequirementError("source selector exceeds the byte bound")
    value = safe_json_loads(registry.get_bytes(record.sha256), max_bytes=_MAX_SELECTOR_BYTES)
    if not isinstance(value, Mapping):
        raise GpuValidationRequirementError("source selector is not an object")
    return value


def _input_identity(spec: FrozenRunSpec) -> tuple[str, str, str, str]:
    return (spec.code_sha256, spec.data_sha256,
            spec.configuration_sha256, spec.evaluator_sha256)


def _same_work(candidate: FrozenRunSpec, selected: FrozenRunSpec,
               candidate_contract: str | None, contract_sha256: str) -> bool:
    return (
        (candidate_contract == contract_sha256
         and candidate.hypothesis_id == selected.hypothesis_id
         and candidate.experiment_id == selected.experiment_id)
        or candidate.project_definition_sha256 == selected.project_definition_sha256
        or _input_identity(candidate) == _input_identity(selected)
    )


def _json_strings_and_keys(value: Any) -> tuple[set[str], set[str]]:
    """Bounded selector traversal only; strings do not confer source authority."""
    pending = [(value, 0)]
    strings: set[str] = set()
    keys: set[str] = set()
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > 250_000 or depth > 64:
            raise GpuValidationRequirementError("progress selector exceeds its shape bound")
        if type(item) is str:
            strings.add(item)
        elif isinstance(item, Mapping):
            keys.update(item)
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, (tuple, list)):
            pending.extend((child, depth + 1) for child in item)
    return strings, keys


def _work_progress(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    records: tuple[ArtifactRecord, ...],
    events: tuple[LedgerEvent, ...],
    *,
    selected: FrozenRunSpec,
    cloud: FrozenRunSpec,
    contract_record: ArtifactRecord,
    escalation_record: ArtifactRecord,
    expected_ledger_run_id: str,
) -> tuple[GpuValidationRequirementStatus, str] | None:
    """Refuse all retained progress, including failed/non-evidentiary attempts.

    Candidate specs here are selectors, not positive scientific owners. Their
    registered bytes may only enlarge the refusal set. A malformed known spec
    or a progress record whose work cannot be classified fails closed.
    """
    if len(records) > MAX_REGISTRY_RECORDS:
        raise GpuValidationRequirementError("progress inventory exceeds registry capacity")
    by_sha = {record.sha256: record for record in records}
    specs: dict[str, FrozenRunSpec] = {}
    matching_roots: set[str] = set()
    matching_tokens = {escalation_record.sha256}
    for initial in (selected, cloud):
        matching_tokens.update((initial.sha256, initial.run_id,
                                initial.project_definition_sha256,
                                initial.scientific_binding_sha256))
    for record in records:
        if record.logical_type not in _SPEC_TYPES:
            continue
        value = _mapping(registry, record)
        if record.logical_type in {
            COMPUTE_ESCALATION_LOCAL_SPEC_LOGICAL_TYPE,
            COMPUTE_ESCALATION_CLOUD_SPEC_LOGICAL_TYPE,
        }:
            value = value.get("value")
        candidate = _parse_frozen_run_spec(value)
        specs[record.sha256] = candidate
        parent = by_sha.get(record.parent_artifacts[0]) if record.parent_artifacts else None
        contract_hash = (parent.sha256 if parent is not None
                         and parent.logical_type == "evaluation_contract" else None)
        tokens = {record.sha256, candidate.sha256, candidate.run_id,
                  candidate.project_definition_sha256, candidate.scientific_binding_sha256}
        if _same_work(candidate, selected, contract_hash, contract_record.sha256):
            matching_roots.add(record.sha256)
            matching_tokens.update(tokens)

    children: dict[str, list[str]] = {}
    for record in records:
        for parent in record.parent_artifacts:
            children.setdefault(parent, []).append(record.sha256)

    def descendants(roots: set[str]) -> set[str]:
        found = set(roots)
        pending = list(roots)
        while pending:
            for child in children.get(pending.pop(), ()):
                if child not in found:
                    found.add(child)
                    pending.append(child)
            if len(found) > MAX_REGISTRY_RECORDS:
                raise GpuValidationRequirementError("progress ancestry exceeds registry capacity")
        return found

    matching_records = descendants(matching_roots | {escalation_record.sha256})
    # A stray unrelated token or extra parent must never narrow the refusal
    # set. Only this complete existing owner establishes supported unrelated
    # preparation; arbitrary descendants and other progress remain unknown.
    unrelated_records: set[str] = set()
    unrelated_events: set[tuple[int, str, str | None]] = set()
    for record in records:
        if record.logical_type != "scientific_execution_preparation":
            continue
        selector = _mapping(registry, record)
        spec_hash = selector.get("frozen_run_spec_artifact_sha256")
        if (type(spec_hash) is not str or spec_hash not in specs
                or spec_hash in matching_roots or record.sha256 in matching_records):
            continue
        preparation = require_scientific_execution_preparation(
            registry, ledger, preparation_artifact_sha256=record.sha256,
            expected_ledger_run_id=expected_ledger_run_id,
            expected_execution_run_id=specs[spec_hash].run_id,
        )
        if (preparation.frozen_run_spec_artifact_sha256 != spec_hash
                or preparation.frozen_run_spec_sha256 != specs[spec_hash].sha256):
            raise GpuValidationRequirementError("unrelated preparation changed its exact spec")
        unrelated_records.update((record.sha256,
                                  preparation.execution_plan_artifact_sha256,
                                  preparation.execution_input_binding_artifact_sha256))
        unrelated_events.add((preparation.ledger_event_index,
                              preparation.ledger_event_id, preparation.ledger_event_hash))
    for record in records:
        if not (record.logical_type in _PROGRESS_TYPES
                or record.logical_type.startswith(_PROGRESS_PREFIXES)):
            continue
        # GPU source/target specs are published only on actual artifact return.
        if record.sha256 in matching_records:
            return GpuValidationRequirementStatus.WORK_ALREADY_STARTED, "RETAINED_WORK_PROGRESS"
        strings: set[str] = set()
        if record.mime_type == "application/json":
            strings, _ = _json_strings_and_keys(_mapping(registry, record))
        if strings & matching_tokens:
            return GpuValidationRequirementStatus.WORK_ALREADY_STARTED, "RETAINED_WORK_PROGRESS"
        if record.sha256 not in unrelated_records:
            return GpuValidationRequirementStatus.BLOCKED_LOCAL, "UNCLASSIFIABLE_RETAINED_PROGRESS"

    for index, event in enumerate(events):
        strings, keys = _json_strings_and_keys(event.metadata)
        external = "compute_escalation_submission_consumption" in keys
        timeline = event.metadata.get("scientific_timeline")
        timeline_progress = "scientific_timeline" in event.metadata and (
            not isinstance(timeline, Mapping)
            or timeline.get("kind") != "DESIGN_FROZEN"
            or timeline.get("output_manifest_artifact_sha256") is not None
        )
        progress = (
            external
            or "operational_seed_admission" in keys
            or "operational_best_of_n_report" in keys
            or any(key.startswith(("scientific_execution", "scheduled_gpu_")) for key in keys)
            or event.event_type in {"CONFIRMATORY_STARTED", "CONFIRMATORY_COMPLETED"}
            or timeline_progress
        )
        if not progress:
            continue
        if (index, event.event_id, event.event_hash) in unrelated_events:
            continue
        related = bool(strings & matching_tokens or set(event.artifact_hashes) & matching_records)
        if isinstance(timeline, Mapping):
            related = related or (
                timeline.get("contract_artifact_sha256") == contract_record.sha256
                and timeline.get("hypothesis_id") == selected.hypothesis_id
                and timeline.get("experiment_id") == selected.experiment_id
            )
        if related:
            if external:
                return GpuValidationRequirementStatus.BLOCKED_EXTERNAL, "EXTERNAL_ACTION_CONSUMPTION_PRESENT"
            return GpuValidationRequirementStatus.WORK_ALREADY_STARTED, "LEDGER_WORK_PROGRESS"
        return (
            GpuValidationRequirementStatus.BLOCKED_EXTERNAL if external
            else GpuValidationRequirementStatus.BLOCKED_LOCAL,
            "UNCLASSIFIABLE_EXTERNAL_EFFECT" if external else "UNCLASSIFIABLE_LEDGER_PROGRESS",
        )
    return None


def _source_closure(records: tuple[ArtifactRecord, ...],
                    roots: tuple[ArtifactRecord, ...]) -> tuple[ArtifactRecord, ...]:
    by_sha = {record.sha256: record for record in records}
    found: dict[str, ArtifactRecord] = {}
    pending = list(reversed(roots))
    while pending:
        record = pending.pop()
        if record.sha256 in found:
            continue
        if by_sha.get(record.sha256) != record or record.record_hash is None:
            raise GpuValidationRequirementError("source record differs from the entry snapshot")
        found[record.sha256] = record
        if len(found) > MAX_ARTIFACT_PARENTS:
            raise GpuValidationRequirementError("requirement source closure exceeds 256 parents")
        for digest in reversed(record.parent_artifacts):
            if digest not in by_sha:
                raise GpuValidationRequirementError("requirement source parent is unavailable")
            pending.append(by_sha[digest])
    return tuple(found.values())


def _derive_requirement(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    evaluation_contract_freeze_receipt_artifact_sha256: str,
    compute_escalation_plan_authority_artifact_sha256: str,
    entry_registry: RegistryValidationResult,
    entry_ledger: LedgerValidationResult,
) -> GpuValidationRequirementResolution:
    freeze_record = registry.get_metadata(evaluation_contract_freeze_receipt_artifact_sha256)
    freeze_selector = EvaluationContractFreezeGateReceipt.from_dict(_mapping(registry, freeze_record))
    freeze = require_evaluation_contract_freeze_gate_receipt(
        registry, ledger, receipt_artifact_sha256=freeze_record.sha256,
        expected_run_id=expected_ledger_run_id, expected_contract_id=freeze_selector.object_id,
    )
    contract = require_frozen_evaluation_contract(
        registry, contract_artifact_sha256=freeze.contract_artifact_sha256,
    )
    contract_record = registry.get_metadata(freeze.contract_artifact_sha256)
    local_record, local, input_records = _require_scientific_execution_spec_and_inputs(
        registry, freeze.frozen_run_spec_artifact_sha256,
    )
    if local.run_id != expected_execution_run_id:
        raise GpuValidationRequirementError("canonical local spec names another execution")
    metadata = thaw_json(local.metadata)
    if GPU_VALIDATION_REQUIREMENT_POLICY_METADATA_KEY not in metadata:
        return _unavailable(GpuValidationRequirementStatus.NOT_APPLICABLE, "NO_DEVICE_REQUIREMENT_POLICY")
    if metadata[GPU_VALIDATION_REQUIREMENT_POLICY_METADATA_KEY] != {
        "schema_version": GPU_VALIDATION_REQUIREMENT_POLICY_SCHEMA,
        "profile_id": CUDA_DEVICE_TIMING_PROFILE_ID,
    }:
        raise GpuValidationRequirementError("device requirement policy is not the closed v1 profile")

    escalation_record = registry.get_metadata(compute_escalation_plan_authority_artifact_sha256)
    selector = ComputeEscalationPlanAuthority.from_dict(_mapping(registry, escalation_record))
    escalation = require_compute_escalation_plan_authority(
        registry, ledger, authority_artifact_sha256=escalation_record.sha256,
        expected_run_id=expected_ledger_run_id, expected_decision_id=selector.object_id,
    )
    _, local_value = _load_compute_escalation_input(
        registry, escalation.local_spec_artifact_sha256, run_id=expected_ledger_run_id,
        logical_type=COMPUTE_ESCALATION_LOCAL_SPEC_LOGICAL_TYPE, creator_role=Role.EXPERIMENT_RUNNER,
    )
    _, cloud_value = _load_compute_escalation_input(
        registry, escalation.cloud_spec_artifact_sha256, run_id=expected_ledger_run_id,
        logical_type=COMPUTE_ESCALATION_CLOUD_SPEC_LOGICAL_TYPE, creator_role=Role.EXPERIMENT_RUNNER,
    )
    cloud = _parse_frozen_run_spec(cloud_value)
    if (local != _parse_frozen_run_spec(local_value)
            or canonical_json_bytes(local.to_dict()) != canonical_json_bytes(local_value)
            or cloud.project_definition_sha256 != local.project_definition_sha256
            or local.compute_profile.mode is not ComputeMode.LOCAL_MAC
            or local.compute_profile.accelerator not in {AcceleratorKind.CPU, AcceleratorKind.MPS}
            or cloud.compute_profile.mode is not ComputeMode.GPU_CLOUD
            or cloud.compute_profile.accelerator is not AcceleratorKind.CUDA
            or cloud.compute_profile.validation_status is not ValidationStatus.UNTESTED
            or cloud.evidence_class is not EvidenceClass.SCIENTIFIC_RESULT_ELIGIBLE
            or cloud.attempt != 1 or cloud.retry_of_run_id is not None):
        raise GpuValidationRequirementError("freeze and escalation do not own the same fresh protocol")

    input_bytes = tuple(registry.get_bytes(record.sha256) for record in input_records)
    code, data, configuration, evaluator = input_bytes
    protocol = CudaDeviceTimingProtocol.from_mapping(safe_json_loads(configuration))
    if (configuration != protocol.canonical_bytes()
            or code != CUDA_DEVICE_TIMING_BENCHMARK_BYTES
            or evaluator != CUDA_DEVICE_TIMING_EVALUATOR_BYTES
            or local.argv != protocol.expected_argv() or cloud.argv != protocol.expected_argv()
            or local.working_directory != "." or cloud.working_directory != "."):
        raise GpuValidationRequirementError("retained CUDA inputs or launch intent differ")
    validate_cuda_device_timing_dataset(protocol, data)

    plan_records = tuple(registry.get_metadata(digest) for digest in freeze.experiment_plan_artifact_sha256s)
    # The complete freeze owner above owns these exact ordered wrappers/records.
    plans = tuple(ExperimentPlan.from_dict(_mapping(registry, record)["plan"]) for record in plan_records)
    primary = contract.hypothesis_register.primary
    metric = contract.primary_metric
    baseline = contract.baseline_registry.baseline(protocol.baseline_id)
    if (primary.hypothesis_id != local.hypothesis_id
            or primary.planned_experiment != local.experiment_id
            or protocol.seeds != local.seeds or protocol.seeds != contract.seed_reporting.seeds
            or tuple(plan.seed for plan in plans) != protocol.seeds
            or metric.metric_id != protocol.metric_id
            or metric.unit is not MetricUnit.MILLISECONDS
            or metric.direction is not MetricDirection.LOWER_IS_BETTER
            or metric.scope is not MetricScope.INTERMEDIATE
            or metric.definition != CUDA_DEVICE_TIMING_METRIC_DEFINITION
            or metric.aggregation != CUDA_DEVICE_TIMING_METRIC_AGGREGATION
            or baseline.status is not BaselineStatus.MUST_RUN
            or baseline.exclusion is not None
            or baseline.conditions != contract.candidate_conditions
            or any(plan.evaluator_id != contract.candidate_conditions.evaluator for plan in plans)):
        raise GpuValidationRequirementError("CUDA protocol is not one exact mandatory primary obligation")

    freeze_index, escalation_index = freeze.design_freeze_event_index, escalation.ledger_event_index
    if not (0 <= freeze_index < len(entry_ledger.events)
            and 0 <= escalation_index < len(entry_ledger.events)):
        raise GpuValidationRequirementError("source admissions are outside the entry prefix")
    freeze_event, escalation_event = entry_ledger.events[freeze_index], entry_ledger.events[escalation_index]
    if ((freeze_event.event_id, freeze_event.event_hash)
            != (freeze.design_freeze_event_id, freeze.design_freeze_event_hash)
            or (escalation_event.event_id, escalation_event.event_hash)
            != (escalation.ledger_event_id, escalation.ledger_event_hash)):
        raise GpuValidationRequirementError("source admission identity changed")
    # Neither admission must precede the other: both are prospective, and a
    # future publisher must bind both before its own event. No timestamp order
    # is invented beyond the ordinary full source owners' rules.
    progress = _work_progress(
        registry, ledger, entry_registry.records, entry_ledger.events,
        selected=local, cloud=cloud, contract_record=contract_record,
        escalation_record=escalation_record,
        expected_ledger_run_id=expected_ledger_run_id,
    )
    if progress is not None:
        return _unavailable(*progress)
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
        return _unavailable(
            GpuValidationRequirementStatus.BLOCKED_LOCAL,
            "OPERATIONAL_RESERVATION_OR_POSSIBLE_PROGRESS",
        )
    escalation_inputs = tuple(registry.get_metadata(digest) for digest in escalation.input_artifact_hashes)
    owned_values = tuple(_mapping(registry, record)["value"] for record in escalation_inputs)
    sources = _source_closure(entry_registry.records, (freeze_record, escalation_record))
    return GpuValidationRequirementResolution(
        GpuValidationRequirementStatus.REQUIREMENT_ESTABLISHED,
        "DECLARED_CUDA_QUANTITY_OUTSIDE_ADMITTED_LOCAL_CAPABILITIES",
        GpuValidationRequirement(
            freeze_record=freeze_record, freeze=freeze,
            contract_record=contract_record, contract=contract,
            plan_records=plan_records, plans=plans,
            local_spec_record=local_record, local_spec=local, cloud_spec=cloud,
            escalation_record=escalation_record, escalation=escalation,
            escalation_input_records=escalation_inputs,
            decision=_parse_escalation_decision(owned_values[7]),
            submission_plan=_parse_submission_plan(owned_values[8]),
            budget=_parse_escalation_budget(owned_values[6]),
            human_gate_policy=_parse_human_gate_policy(owned_values[5]),
            protocol=protocol, input_records=input_records, input_bytes=input_bytes,
            source_records=sources, entry_registry_snapshot=entry_registry,
            entry_ledger_snapshot=entry_ledger, freeze_event=freeze_event,
            escalation_event=escalation_event,
        ),
    )


def _resolve_gpu_validation_requirement(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    evaluation_contract_freeze_receipt_artifact_sha256: str,
    compute_escalation_plan_authority_artifact_sha256: str,
    project_lock_held: bool = False,
) -> GpuValidationRequirementResolution:
    """Same full owner for a future publisher already holding the project lock."""
    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise GpuValidationRequirementError("GPU requirement requires exact registry and ledger")
    for value, label, validator in (
        (expected_ledger_run_id, "ledger run ID", validate_identifier),
        (expected_execution_run_id, "execution run ID", validate_identifier),
        (evaluation_contract_freeze_receipt_artifact_sha256, "freeze SHA-256", validate_sha256),
        (compute_escalation_plan_authority_artifact_sha256, "escalation SHA-256", validate_sha256),
    ):
        if type(value) is not str:
            raise GpuValidationRequirementError(f"{label} must be exact native text")
        validator(value, label)
    if type(project_lock_held) is not bool:
        raise GpuValidationRequirementError("project lock state must be exact native boolean")
    arguments = dict(
        expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_execution_run_id,
        evaluation_contract_freeze_receipt_artifact_sha256=evaluation_contract_freeze_receipt_artifact_sha256,
        compute_escalation_plan_authority_artifact_sha256=compute_escalation_plan_authority_artifact_sha256,
    )
    if not project_lock_held:
        try:
            with _project_resource_execution_lock(registry.policy.root):
                return _resolve_gpu_validation_requirement(registry, ledger, **arguments, project_lock_held=True)
        except (OrchestrationError, OSError):
            return _unavailable(GpuValidationRequirementStatus.BLOCKED_LOCAL, "PROJECT_RESOURCE_LOCK_UNAVAILABLE")
    try:
        entry_registry, entry_ledger = _locked_resource_registry_ledger_snapshot(registry, ledger, expected_ledger_run_id)
    except (ArtifactError, LedgerError, OrchestrationError, ValidationError):
        return _unavailable(GpuValidationRequirementStatus.BLOCKED_LOCAL, "SOURCE_SNAPSHOT_UNAVAILABLE")
    try:
        resolution = _derive_requirement(
            registry, ledger, **arguments, entry_registry=entry_registry, entry_ledger=entry_ledger,
        )
    except (ArtifactError, LedgerError, OrchestrationError, ExperimentError,
            ScientificDesignError, ValidationError, KeyError, TypeError, ValueError):
        resolution = _unavailable(GpuValidationRequirementStatus.BLOCKED_LOCAL, "SOURCE_REQUIREMENT_UNAVAILABLE")
    try:
        final = _locked_resource_registry_ledger_snapshot(registry, ledger, expected_ledger_run_id)
    except (ArtifactError, LedgerError, OrchestrationError, ValidationError):
        return _unavailable(GpuValidationRequirementStatus.BLOCKED_LOCAL, "SOURCE_SNAPSHOT_UNAVAILABLE")
    if final != (entry_registry, entry_ledger):
        return _unavailable(GpuValidationRequirementStatus.BLOCKED_LOCAL, "SOURCES_CHANGED_DURING_RESOLUTION")
    return resolution


def resolve_gpu_validation_requirement(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    evaluation_contract_freeze_receipt_artifact_sha256: str,
    compute_escalation_plan_authority_artifact_sha256: str,
) -> GpuValidationRequirementResolution:
    """Fresh, nonissuing prospective requirement replay under the project lock."""
    return _resolve_gpu_validation_requirement(
        registry, ledger, expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_execution_run_id,
        evaluation_contract_freeze_receipt_artifact_sha256=evaluation_contract_freeze_receipt_artifact_sha256,
        compute_escalation_plan_authority_artifact_sha256=compute_escalation_plan_authority_artifact_sha256,
    )
