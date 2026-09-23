"""Offline, resumable orchestration for the bounded Scientist-One workflow."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from functools import wraps
import hashlib
import fcntl
import math
import os
from pathlib import Path
import re
import stat
import sys
import threading
import uuid
from typing import Any, Callable, Iterator, Mapping, Sequence

from .artifacts import (
    MAX_ARTIFACT_OBJECT_BYTES,
    MAX_REGISTRY_RECORDS,
    ArtifactRecord,
    ArtifactRegistry,
)
from .calibration import assert_calibrated, run_calibration, run_synthetic_workflow_benchmark
from .claims import (
    ClaimDecision,
    ClaimEvidenceUse,
    ClaimEvidenceGraph,
    EvidenceKind,
    EvidenceLink,
    EvidenceNode,
    EvidenceSupportReceipt,
    MaterialClaim,
    artifact_registry_resolver,
)
from .device import DeviceManager, HardwareProfiler
from .external import (
    EGRESS_ATTEMPT_SCHEMA,
    EGRESS_BUDGET_SCHEMA,
    EGRESS_REQUEST_SCHEMA,
    EGRESS_RESPONSE_RECEIPT_SCHEMA,
)
from .experiments import FrozenRunSpec
from .evaluators import (
    AuditSummary,
    Decision,
    Evaluation,
    EvaluatorClass,
    REQUIRED_R_AUTHORITIES,
    RCheck,
    register_r_check_authority,
    register_r_check_authority_bundle,
)
from .holdout import ConfirmatoryEvaluatorSpec, SimulatedHoldoutCustody
from .ledger import MAX_LEDGER_BYTES, MAX_LEDGER_EVENTS, EventLedger, LedgerEvent
from .models import (
    ArtifactRef,
    MacroState,
    TerminalState,
    TransitionRequest,
    parse_state,
    thaw_json,
)
from .packaging import _assert_gateway_trust_root_not_serialized, package_run
from .protocol import (
    BaselineSpec,
    ConfidenceIntervalSpec,
    DataRoles,
    DomainNullSpec,
    ExecutionConditions,
    InterpretationRules,
    ProtocolComputeBudget,
    ResearchProtocol,
    SeedPolicy,
    StatisticalTestSpec,
    freeze_protocol,
    validate_protocol,
)
from .recovery import (
    ConfirmatoryRevealAuthority,
    FreshCustodyEvidence,
    RecoveryManager,
    RegisteredArtifactSelector,
)
from .reproduction import (
    ARCHITECTURE_CONTROL_REPLAY_STATUS,
    reproduce_architecture_control_run,
    reproduce_run,
    verify_frozen_architecture_control_reproduction,
    verify_frozen_reproduction,
)
from .readiness import evaluate_readiness, register_frozen_readiness_rubric
from .resources import (
    ResourceConfig,
    ResourceController,
    ResourceLimitError,
    ResourceRuntimeState,
    _ResourceAdmissionRefusal,
    _replay_resource_admission,
    ValidityBudget,
    ValidityBudgetSnapshot,
    resource_config_sha256,
)
from .roles import Role, make_role_bundle
from .security import (
    PathSecurityError,
    atomic_write_bytes,
    atomic_write_json,
    canonical_json_bytes,
    open_confined_directory_fd,
    read_confined_bytes,
    safe_json_loads,
    secure_directory as secure_directory_shared,
)
from .state_machine import (
    LEGACY_EVALUATION_RECEIPT_KEYS,
    StateController,
    TransitionContract,
    TransitionResult,
    default_transition_contracts,
    legacy_evaluation_receipt,
    macro_transition_contracts,
    validate_legacy_transition_prefix,
)
from .writing import (
    render_demo_paper_bytes,
    render_results_table_bytes,
    render_svg_effect_figure_bytes,
    write_demo_paper,
    write_results_table,
    write_svg_effect_figure,
)


SCHEMA_VERSION = "1.0"
MAX_INVENTORY_ENTRIES = 2_048
MAX_INVENTORY_TOTAL_BYTES = 64 * 1024 * 1024
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RESOURCE_AUTHORITY_NAME_PATTERN = re.compile(
    r"^(?P<sequence>[0-9]{4})-(?P<digest>[0-9a-f]{64})\.json$"
)
RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE = (
    "resource_runtime_wall_budget_observation"
)
RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_SCHEMA = (
    "resource-runtime-wall-budget-observation/v1"
)
RESOURCE_RUNTIME_ADMISSION_REFUSAL = "resource_runtime_admission_refusal"
RESOURCE_RUNTIME_PILOT_FAILURE = "resource_runtime_pilot_failure"
_PILOT_FAILURE_SCHEMA = "pilot-call-failure/v1"
_PILOT_FAILURE_REASON = "owned pilot callable raised; retained outputs are incomplete"
_PILOT_FAILURE_FIELDS = {
    "schema_version", "kind", "run_id", "state", "owner", "request", "reason",
    "diagnostic_kind", "recorded_at", "creation_command", "authority_scope",
    "scientific_evidence", "retry_allowed", "charge_artifact_sha256",
    "charge_record_hash", "charge_event_id", "prior_authority_sha256",
    "base_manifest_sha256", "base_manifest_updated_at", "base_event_count",
    "base_ledger_head_hash", "base_registry_identities", "base_file_inventory",
    "base_checkpoint", "source_context", "incomplete_output_prefix",
    "prefix_disposition", "runtime_state", "observation_scope",
}
_RESOURCE_ADMISSION_SCHEMA = "resource-admission-refusal/v1"
_RESOURCE_ADMISSION_REASON = "source-owned admission refusal; no work or validity charge admitted"
_RESOURCE_ADMISSION_FIELDS = {
    "schema_version", "kind", "run_id", "state", "resource_config",
    "observation", "prior_authority_sha256", "source_registry_identities",
    "source_event_count", "source_ledger_head_hash", "source_manifest_sha256",
    "source_manifest_updated_at", "creation_command", "recorded_at",
    "authority_scope", "scientific_evidence",
}
_RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_ORIGIN = (
    "source-owned monotonic run wall-budget observation"
)
_RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_COMMAND = (
    "scientist-one",
    "observe-run-wall-budget",
)
_BUILTIN_OFFLINE_ARTIFACT_ORIGIN = "Scientist-One built-in offline workflow"
_LEGACY_RESOURCE_RUNTIME_STAGE_SEQUENCES = frozenset(
    {
        ("resource_runtime_initial",),
        (
            "resource_runtime_initial",
            "resource_runtime_pilot_charge",
            "resource_runtime_pilot_completion",
        ),
        (
            "resource_runtime_initial",
            "resource_runtime_confirmatory_charge",
            "resource_runtime_confirmatory_completion",
        ),
        (
            "resource_runtime_initial",
            "resource_runtime_pilot_charge",
            "resource_runtime_pilot_completion",
            "resource_runtime_confirmatory_charge",
            "resource_runtime_confirmatory_completion",
        ),
    }
)
MACRO_STATES = (
    "CALIBRATE",
    "CHARTER",
    "GROUND",
    "PROTOCOL",
    "PREFLIGHT",
    "IDEATE",
    "DISCOVER",
    "CANDIDATE",
    "CONFIRM",
    "CLAIMS",
    "WRITE",
    "AUDIT",
    "RELEASE",
)
TERMINAL_STATES = {
    "READY_FOR_HUMAN_REVIEW",
    "NEGATIVE_RESULT",
    "INCONCLUSIVE",
    "BLOCKED_EXTERNAL",
    "STOP_SCIENTIFIC_INVALIDITY",
    "STOP_SECURITY",
    "STOP_BUDGET",
}

VNEXT_LEGACY_OPERATION_SCHEMA_VERSION = "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V1"
VNEXT_OPERATION_SCHEMA_VERSION = "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V2"
VNEXT_RESTART_OPERATION_SCHEMA_VERSION = "SCIENTIST_ONE_RESEARCH_OS_OPERATION_V3"
VNEXT_VERIFICATION_SCHEMA_VERSION = "SCIENTIST_ONE_RESEARCH_OS_VERIFICATION_V2"
VNEXT_STATUS_SCHEMA_VERSION = "SCIENTIST_ONE_RESEARCH_OS_STATUS_V2"
VNEXT_GUARDED_LAUNCH_SCHEMA_VERSION = "SCIENTIST_ONE_GUARDED_LAUNCH_V1"
VNEXT_RESTART_LINEAGE_SCHEMA_VERSION = "SCIENTIST_ONE_RESEARCH_OS_RESTART_LINEAGE_V1"
VNEXT_MAX_RESTART_LINEAGE_DEPTH = 32
VNEXT_DIRECT_LAUNCH_MODE = "DIRECT_TEST_API"
VNEXT_GUARDED_LAUNCH_MODE = "GUARDED_PRODUCTION"
VNEXT_LEGACY_LAUNCH_MODE = "UNKNOWN_LEGACY"
VNEXT_FIXTURE_SCHEMA_VERSION = "SCIENTIST_ONE_RESEARCH_OS_FIXTURE_V1"
VNEXT_FIXTURE_NOTICE = (
    "Synthetic integration fixture only; no publishable scientific conclusion."
)
VNEXT_OPERATION_STATUS_POLICY = {
    "IN_PROGRESS": "IN_PROGRESS_NO_DOWNSTREAM_AUTHORITY",
    "FAILED": "FAIL_CLOSED_START_NEW_RUN_ID",
    "COMPLETE": "IMMUTABLE_COMPLETE",
}


class OrchestrationError(RuntimeError):
    """A typed workflow contract, custody rule, or safety check failed."""


class _ResourceAdmissionBlocked(OrchestrationError):
    """A complete sticky operational refusal, never scientific authority."""


@dataclass(frozen=True, slots=True)
class ResourceRuntimeWallBudgetObservation:
    """Fresh projection of one ledger-bound monotonic wall-budget observation."""

    run_id: str
    resource_config: ResourceConfig
    runtime_state: ResourceRuntimeState
    frozen_configuration_inventory_artifact_sha256: str
    frozen_configuration_inventory_record_hash: str
    prior_resource_runtime_artifact_sha256: str
    observation_artifact_sha256: str
    observation_record_hash: str
    external_authority_sequence: int
    external_authority_sha256: str
    ledger_event_id: str
    ledger_event_hash: str
    ledger_event_index: int

    def __post_init__(self) -> None:
        if not RUN_ID_PATTERN.fullmatch(self.run_id):
            raise OrchestrationError("wall-budget observation run ID is invalid")
        if type(self.resource_config) is not ResourceConfig or type(
            self.runtime_state
        ) is not ResourceRuntimeState:
            raise OrchestrationError(
                "wall-budget observation requires typed resource state"
            )
        if self.runtime_state.run_id != self.run_id:
            raise OrchestrationError("wall-budget observation names another run")
        for name in (
            "frozen_configuration_inventory_artifact_sha256",
            "frozen_configuration_inventory_record_hash",
            "prior_resource_runtime_artifact_sha256",
            "observation_artifact_sha256",
            "observation_record_hash",
            "external_authority_sha256",
            "ledger_event_hash",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise OrchestrationError(f"wall-budget observation {name} is invalid")
        if (
            isinstance(self.external_authority_sequence, bool)
            or not isinstance(self.external_authority_sequence, int)
            or self.external_authority_sequence < 1
            or isinstance(self.ledger_event_index, bool)
            or not isinstance(self.ledger_event_index, int)
            or self.ledger_event_index < 0
            or not isinstance(self.ledger_event_id, str)
            or not self.ledger_event_id
        ):
            raise OrchestrationError("wall-budget observation position is invalid")


_GUARDED_LAUNCH_SEAL = object()


class _GuardedLaunchCapability:
    """One-shot in-process proof that the captured production path admitted a run."""

    __slots__ = (
        "_command_context",
        "_consumed",
        "_owner",
        "_requested_run_id",
        "_restart_from_run_id",
        "_restart_lineage_consumed",
        "_restart_source_guarded_receipt_sha256",
        "_restart_source_operation_sha256",
        "_restart_source_operation_schema_version",
        "_root",
        "_root_identity",
        "_seal",
        "_source_inventory_bytes",
    )

    def __init__(
        self,
        *,
        seal: object,
        owner: object,
        root: Path,
        root_identity: tuple[int, int],
        requested_run_id: str | None,
        restart_from_run_id: str | None,
        restart_source_operation_sha256: str | None,
        restart_source_operation_schema_version: str | None,
        restart_source_guarded_receipt_sha256: str | None,
        command_context: tuple[str, ...],
        source_inventory_bytes: bytes,
    ) -> None:
        if seal is not _GUARDED_LAUNCH_SEAL:
            raise OrchestrationError("guarded launch capability seal is invalid")
        self._seal = seal
        self._owner = owner
        self._root = root
        self._root_identity = root_identity
        self._requested_run_id = requested_run_id
        self._restart_from_run_id = restart_from_run_id
        self._restart_source_operation_sha256 = restart_source_operation_sha256
        self._restart_source_operation_schema_version = (
            restart_source_operation_schema_version
        )
        self._restart_source_guarded_receipt_sha256 = (
            restart_source_guarded_receipt_sha256
        )
        self._restart_lineage_consumed = False
        self._command_context = command_context
        self._source_inventory_bytes = source_inventory_bytes
        self._consumed = False


@dataclass(frozen=True)
class _ChargedResourceAuthority:
    """Exact post-charge authority passed only to a custody-bound operation."""

    selector: RegisteredArtifactSelector
    ledger_event_id: str
    validity_snapshot: ValidityBudgetSnapshot
    validity_units: int


def _captured_dispatch_loader() -> object | None:
    """Return the exact active production or evidence captured-source loader."""

    production = getattr(sys, "_scientist_one_isolated_launcher", False) is True
    evidence_present = (
        "_scientist_one_captured_evidence_capability" in sys.__dict__
    )
    if production and evidence_present:
        raise OrchestrationError("captured dispatch authority is ambiguous")
    if not production and not evidence_present:
        return None
    if evidence_present:
        if "_scientist_one_isolated_launcher" in sys.__dict__:
            raise OrchestrationError("captured evidence authority is ambiguous")
        test_authority = sys.__dict__.get("_scientist_one_test_runner")
        if test_authority is not None and test_authority is not True:
            raise OrchestrationError("captured evidence test authority is invalid")
        capability = sys.__dict__["_scientist_one_captured_evidence_capability"]
    else:
        capability = globals().get("__loader__")

    module_loader = globals().get("__loader__")
    tree = getattr(capability, "tree", None)
    records = getattr(tree, "records", None)
    record = records.get(__name__) if isinstance(records, dict) else None
    executed = getattr(capability, "executed", None)
    if (
        capability is not module_loader
        or getattr(globals().get("__spec__"), "loader", None) is not capability
        or not sys.meta_path
        or sys.meta_path[0] is not capability
        or sum(item is capability for item in sys.meta_path) != 1
        or type(capability).__module__ != "__main__"
        or type(capability).__name__ != "_CapturedSourceLoader"
        or not isinstance(getattr(tree, "root", None), Path)
        or not isinstance(getattr(tree, "root_identity", None), os.stat_result)
        or record is None
        or not isinstance(getattr(record, "path", None), Path)
        or record.path != Path(__file__)
        or not isinstance(getattr(record, "identity", None), os.stat_result)
        or not isinstance(getattr(record, "sha256", None), str)
        or not isinstance(executed, dict)
        or executed.get(__name__) != record.sha256
    ):
        raise OrchestrationError("captured dispatch capability is invalid")
    return capability


def _captured_project_root() -> tuple[Path, tuple[int, int]] | None:
    """Return the launcher's admitted root capability during trusted dispatch."""

    production = getattr(sys, "_scientist_one_isolated_launcher", False) is True
    if (
        production
        and getattr(sys, "_scientist_one_test_runner", False) is True
        and "_scientist_one_captured_evidence_capability" not in sys.__dict__
        and getattr(sys, "_scientist_one_captured_source_attestation", None) is None
        and not hasattr(globals().get("__loader__"), "tree")
    ):
        # Explicit normal-loader unit-test compatibility.  The production CLI
        # cannot obtain its dispatch authority from this branch.
        return None
    loader = _captured_dispatch_loader()
    if loader is None:
        return None
    tree = getattr(loader, "tree", None)
    root = getattr(tree, "root", None)
    identity = getattr(tree, "root_identity", None)
    if not isinstance(root, Path) or not isinstance(identity, os.stat_result):
        raise OrchestrationError("captured project-root capability is unavailable")
    return root, (identity.st_dev, identity.st_ino)


TRANSITION_CONTRACTS: dict[str, TransitionContract] = {
    contract.source.value: contract for contract in macro_transition_contracts()
}


def _contract_dict(contract: TransitionContract) -> dict[str, Any]:
    """Stable JSON projection of the one canonical foundation contract."""

    return {
        "source": contract.source.value,
        "destination": contract.destination.value,
        "required_artifacts": sorted(contract.required_artifact_types),
        "required_evaluators": sorted(item.value for item in contract.required_evaluators),
        "requesters": sorted(item.value for item in contract.allowed_requesters),
        "approvers": sorted(item.value for item in contract.allowed_approvers),
        "generated_artifacts": sorted(contract.generated_artifact_types),
        "failure_states": sorted(item.value for item in contract.failure_states),
        "validation_rules": list(contract.validation_rules),
        "idempotency": contract.idempotency_rule,
    }


def _evaluation_key(source: str, evaluator: EvaluatorClass) -> str:
    return f"{evaluator.value}:{source}"


def _terminal_evaluation_key(
    source: str, destination: str, evaluator: EvaluatorClass
) -> str:
    """Keep terminal review receipts distinct from an earlier stage review."""

    return f"{evaluator.value}:{source}->{destination}"


def _evaluation_from_legacy_receipt(stored: Mapping[str, Any]) -> Evaluation:
    """Reconstruct an exact context-bound legacy evaluator authority."""

    if set(stored) != LEGACY_EVALUATION_RECEIPT_KEYS:
        raise ValueError("legacy evaluator receipt schema is incomplete")
    evaluation = Evaluation(
        evaluator_class=EvaluatorClass(stored["evaluator_class"]),
        actor_role=Role(stored["authority"]),
        decision=Decision(stored["decision"]),
        artifact_hashes=tuple(stored["artifact_hashes"]),
        reason=stored["reason"],
        r_checks=tuple(RCheck(item) for item in stored["r_checks"]),
        critical_objection=stored["critical_objection"],
        producer_role=(
            Role(stored["producer_role"])
            if stored["producer_role"] is not None
            else None
        ),
        run_id=stored["run_id"],
        gate_id=stored["gate_id"],
        frozen_context_sha256=stored["frozen_context_sha256"],
        human_independence_claimed=stored["human_independence_claimed"],
    )
    if legacy_evaluation_receipt(evaluation) != dict(stored):
        raise ValueError("legacy evaluator receipt differs from typed authority")
    return evaluation


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_bytes(value: Any) -> bytes:
    try:
        return canonical_json_bytes(value) + b"\n"
    except (TypeError, ValueError) as exc:
        raise OrchestrationError(f"value is not canonical JSON: {exc}") from exc


def _replay_vnext_autonomous_summary_roots(
    autonomous: Mapping[str, Any],
    *,
    provider_neutrality_schema: str,
    registry_records: Mapping[str, Any] | None = None,
) -> tuple[bool, Mapping[str, Any], Mapping[str, Any]]:
    """Classify exact autonomous V1/V2 roots without upgrading history.

    The V1 shape is retained strictly for deterministic historical audit.  It
    has neither a provider-neutrality claim nor the four-input execution
    binding and therefore returns ``False``.  Mixing any adjacent V2 root or
    marker into that old shape is rejected instead of being interpreted as an
    in-place migration.
    """

    expected_summary_fields = {
        "admission_status",
        "artifact_sha256s",
        "canonical_object_ids",
        "execution_state",
        "network_isolation_attested",
        "network_use_status",
        "network_used",
        "provider_status",
        "scientific_evidence",
        "semantic_validation_status",
        "template_id",
    }
    neutrality_schema = autonomous.get("provider_neutrality_schema")
    provider_neutral_v2 = neutrality_schema is not None
    if provider_neutral_v2:
        expected_summary_fields.add("provider_neutrality_schema")
    if set(autonomous) != expected_summary_fields:
        raise OrchestrationError(
            "vNext autonomous implementation verification failed: "
            "autonomous summary has missing or unknown fields"
        )
    if provider_neutral_v2 and neutrality_schema != provider_neutrality_schema:
        raise OrchestrationError(
            "vNext autonomous implementation verification failed: "
            "autonomous summary names an unknown provider-neutrality schema"
        )
    artifacts = autonomous.get("artifact_sha256s")
    object_ids = autonomous.get("canonical_object_ids")
    if not isinstance(artifacts, Mapping) or not isinstance(object_ids, Mapping):
        raise OrchestrationError(
            "vNext autonomous implementation verification failed: "
            "summary autonomous roots are malformed"
        )
    artifact_keys = {
        "catalog",
        "configuration",
        "data",
        "data_derivation",
        "descriptor",
        "evaluator",
        "execution_plan",
        "execution_plan_binding",
        "execution_receipt",
        "frozen_spec",
        "manifest",
        "proposal",
        "semantic_validation",
        "validation_receipt",
        "worker_code",
    }
    if provider_neutral_v2:
        artifact_keys.update(
            {
                "execution_input_binding",
                "provider_admission_link",
                "provider_attempt",
            }
        )
    object_id_keys = {
        "Dataset",
        "Experiment",
        "Implementation",
        "Method",
        "Metric",
        "Result",
        "Run",
    }
    if set(artifacts) != artifact_keys:
        raise OrchestrationError(
            "vNext autonomous implementation verification failed: "
            "autonomous artifact roots has missing or unknown fields"
        )
    if set(object_ids) != object_id_keys:
        raise OrchestrationError(
            "vNext autonomous implementation verification failed: "
            "autonomous canonical roots has missing or unknown fields"
        )
    if registry_records is not None:
        proposal_record = registry_records.get(artifacts["proposal"])
        if provider_neutral_v2:
            provider_attempt_record = registry_records.get(
                artifacts["provider_attempt"]
            )
            provider_link_record = registry_records.get(
                artifacts["provider_admission_link"]
            )
            if (
                artifacts["proposal"] == artifacts["provider_attempt"]
                or proposal_record is None
                or proposal_record.logical_type
                != "autonomous_implementation.actionable_proposal"
                or proposal_record.schema_version != "1.0"
                or provider_attempt_record is None
                or provider_attempt_record.logical_type
                != "autonomous_implementation.model_proposal"
                or provider_attempt_record.schema_version != "1.0"
                or provider_link_record is None
                or provider_link_record.logical_type
                != "autonomous_implementation.provider_admission_link"
                or provider_link_record.schema_version != "1.0"
            ):
                raise OrchestrationError(
                    "vNext autonomous implementation verification failed: "
                    "provider-neutral roots do not match their exact generation"
                )
        elif (
            proposal_record is None
            or proposal_record.logical_type
            != "autonomous_implementation.model_proposal"
            or proposal_record.schema_version != "1.0"
        ):
            raise OrchestrationError(
                "vNext autonomous implementation verification failed: "
                "historical provider-bound proposal metadata is invalid"
            )
    return provider_neutral_v2, artifacts, object_ids


_VNEXT_ADAPTIVE_PLAN_BINDING_FIELDS = frozenset(
    {
        "agreement",
        "backend_id",
        "collected_backend_id",
        "collected_execution_plan_sha256",
        "collected_execution_input_binding_sha256",
        "collected_manifest_sha256",
        "collected_network_isolation_attested",
        "collected_network_used",
        "collected_returned_artifact_sha256s",
        "collected_scientific_evidence",
        "collected_spec_sha256",
        "collected_validation_status",
        "execution_plan_artifact_sha256",
        "execution_plan_sha256",
        "execution_input_binding_artifact_sha256",
        "execution_input_binding_sha256",
        "job_id",
        "run_id",
        "spec_artifact_sha256",
        "spec_sha256",
        "submission_backend_id",
        "submission_execution_plan_sha256",
        "submission_execution_input_binding_sha256",
        "submission_idempotency_key",
        "submission_network_isolation_attested",
        "submission_network_used",
        "submission_scientific_evidence",
        "submission_spec_sha256",
        "submission_state",
        "submission_validation_status",
    }
)

_VNEXT_ADAPTIVE_PLAN_BINDING_V1_FIELDS = frozenset(
    {
        "agreement",
        "backend_id",
        "collected_backend_id",
        "collected_execution_plan_sha256",
        "collected_manifest_sha256",
        "collected_network_isolation_attested",
        "collected_network_used",
        "collected_returned_artifact_sha256s",
        "collected_scientific_evidence",
        "collected_spec_sha256",
        "collected_validation_status",
        "execution_plan_artifact_sha256",
        "execution_plan_sha256",
        "job_id",
        "run_id",
        "spec_artifact_sha256",
        "spec_sha256",
        "submission_backend_id",
        "submission_execution_plan_sha256",
        "submission_idempotency_key",
        "submission_network_isolation_attested",
        "submission_network_used",
        "submission_scientific_evidence",
        "submission_spec_sha256",
        "submission_state",
        "submission_validation_status",
    }
)


def _validate_vnext_adaptive_plan_binding_v1(
    value: Mapping[str, Any],
    *,
    encoded: bytes,
    parent_artifacts: Sequence[str],
    run_id: str,
    spec_artifact_sha256: str,
    spec_sha256: str,
    execution_plan_artifact_sha256: str,
    execution_plan_sha256: str,
    manifest_artifact_sha256: str,
    returned_artifact_sha256s: Sequence[str],
) -> None:
    """Replay the exact pre-input-binding receipt as historical audit only.

    This deliberately does not synthesize the four descriptor-bound inputs now
    required by LOCAL_MAC.  Callers must keep the enclosing provider-neutrality
    status false and must never treat successful V1 replay as current production
    or scientific authority.
    """

    if set(value) != _VNEXT_ADAPTIVE_PLAN_BINDING_V1_FIELDS:
        raise OrchestrationError(
            "historical execution plan binding has missing or unknown fields"
        )
    if encoded != _canonical_bytes(dict(value)):
        raise OrchestrationError(
            "historical execution plan binding is not canonical JSON"
        )
    expected = {
        "agreement": True,
        "backend_id": "local-mac",
        "collected_backend_id": "local-mac",
        "collected_execution_plan_sha256": execution_plan_sha256,
        "collected_manifest_sha256": manifest_artifact_sha256,
        "collected_network_isolation_attested": False,
        "collected_network_used": False,
        "collected_returned_artifact_sha256s": list(
            returned_artifact_sha256s
        ),
        "collected_scientific_evidence": False,
        "collected_spec_sha256": spec_sha256,
        "collected_validation_status": "VALIDATED_LOCAL",
        "execution_plan_artifact_sha256": execution_plan_artifact_sha256,
        "execution_plan_sha256": execution_plan_sha256,
        "job_id": f"local-{spec_sha256[:20]}",
        "run_id": run_id,
        "spec_artifact_sha256": spec_artifact_sha256,
        "spec_sha256": spec_sha256,
        "submission_backend_id": "local-mac",
        "submission_execution_plan_sha256": execution_plan_sha256,
        "submission_idempotency_key": run_id,
        "submission_network_isolation_attested": False,
        "submission_network_used": False,
        "submission_scientific_evidence": False,
        "submission_spec_sha256": spec_sha256,
        "submission_state": "SUCCEEDED",
        "submission_validation_status": "VALIDATED_LOCAL",
    }
    if dict(value) != expected:
        raise OrchestrationError(
            "historical adaptive execution plan custody binding is invalid"
        )
    if tuple(parent_artifacts) != (
        execution_plan_artifact_sha256,
        spec_artifact_sha256,
    ):
        raise OrchestrationError(
            "historical adaptive execution plan custody parent order is invalid"
        )


def _validate_vnext_adaptive_plan_binding(
    value: Mapping[str, Any],
    *,
    encoded: bytes,
    parent_artifacts: Sequence[str],
    run_id: str,
    spec_artifact_sha256: str,
    spec_sha256: str,
    execution_plan_artifact_sha256: str,
    execution_plan_sha256: str,
    registry: ArtifactRegistry,
    execution_input_binding_artifact_sha256: str,
    frozen_spec: FrozenRunSpec,
    manifest_artifact_sha256: str,
    returned_artifact_sha256s: Sequence[str],
) -> None:
    """Recompute the exact local-backend custody binding consumed by verify."""

    if set(value) != _VNEXT_ADAPTIVE_PLAN_BINDING_FIELDS:
        raise OrchestrationError(
            "execution plan binding has missing or unknown fields"
        )
    if encoded != _canonical_bytes(dict(value)):
        raise OrchestrationError("execution plan binding is not canonical JSON")
    expected = {
        "agreement": True,
        "backend_id": "local-mac",
        "collected_backend_id": "local-mac",
        "collected_execution_plan_sha256": execution_plan_sha256,
        "collected_execution_input_binding_sha256": (
            execution_input_binding_artifact_sha256
        ),
        "collected_manifest_sha256": manifest_artifact_sha256,
        "collected_network_isolation_attested": False,
        "collected_network_used": False,
        "collected_returned_artifact_sha256s": list(
            returned_artifact_sha256s
        ),
        "collected_scientific_evidence": False,
        "collected_spec_sha256": spec_sha256,
        "collected_validation_status": "VALIDATED_LOCAL",
        "execution_plan_artifact_sha256": execution_plan_artifact_sha256,
        "execution_plan_sha256": execution_plan_sha256,
        "execution_input_binding_artifact_sha256": (
            execution_input_binding_artifact_sha256
        ),
        "execution_input_binding_sha256": execution_input_binding_artifact_sha256,
        "job_id": f"local-{spec_sha256[:20]}",
        "run_id": run_id,
        "spec_artifact_sha256": spec_artifact_sha256,
        "spec_sha256": spec_sha256,
        "submission_backend_id": "local-mac",
        "submission_execution_plan_sha256": execution_plan_sha256,
        "submission_execution_input_binding_sha256": (
            execution_input_binding_artifact_sha256
        ),
        "submission_idempotency_key": run_id,
        "submission_network_isolation_attested": False,
        "submission_network_used": False,
        "submission_scientific_evidence": False,
        "submission_spec_sha256": spec_sha256,
        "submission_state": "SUCCEEDED",
        "submission_validation_status": "VALIDATED_LOCAL",
    }
    if dict(value) != expected:
        raise OrchestrationError(
            "adaptive execution plan custody binding is invalid"
        )
    if tuple(parent_artifacts) != (
        execution_plan_artifact_sha256,
        execution_input_binding_artifact_sha256,
        spec_artifact_sha256,
    ):
        raise OrchestrationError(
            "adaptive execution plan custody parent order is invalid"
        )
    try:
        registry.verify(execution_input_binding_artifact_sha256, raise_on_error=True)
        input_record = registry.get_metadata(execution_input_binding_artifact_sha256)
        input_bytes = registry.get_bytes(execution_input_binding_artifact_sha256)
        input_value = safe_json_loads(input_bytes, max_bytes=512 * 1024)
    except Exception as exc:
        raise OrchestrationError(
            "execution input binding artifact is absent or corrupt"
        ) from exc
    if (
        input_record.logical_type != "execution_input_binding"
        or input_record.origin != "exact local execution input-byte binding"
        or input_record.creator_role is not Role.EXPERIMENT_RUNNER
        or input_record.creation_command
        != (
            "scientist-one",
            "research-os-fixture",
            "capture-execution-input-binding",
        )
        or input_record.parent_artifacts != (spec_artifact_sha256,)
        or input_record.schema_version != "1.0"
        or input_record.mime_type != "application/json"
        or input_record.validation_result != "PASS"
        or not input_record.frozen
        or not isinstance(input_value, Mapping)
        or input_bytes != _canonical_bytes(dict(input_value))
        or set(input_value)
        != {
            "schema_version",
            "spec_sha256",
            "inputs",
            "consumption",
            "scientific_evidence",
        }
        or input_value.get("schema_version")
        != "SCIENTIST_ONE_LOCAL_MAC_EXECUTION_INPUT_BINDING_V1"
        or input_value.get("spec_sha256") != frozen_spec.sha256
        or input_value.get("consumption") != "PARENT_HELD_READ_DESCRIPTORS"
        or input_value.get("scientific_evidence") is not False
        or not isinstance(input_value.get("inputs"), list)
    ):
        raise OrchestrationError("execution input binding custody is invalid")
    expected_inputs = (
        ("code", frozen_spec.code_sha256, ".py"),
        ("data", frozen_spec.data_sha256, ".bin"),
        ("configuration", frozen_spec.configuration_sha256, ".bin"),
        ("evaluator", frozen_spec.evaluator_sha256, ".bin"),
    )
    observed_inputs = input_value["inputs"]
    if len(observed_inputs) != len(expected_inputs):
        raise OrchestrationError("execution input binding has the wrong input count")
    for value, (kind, digest, suffix) in zip(observed_inputs, expected_inputs):
        try:
            payload = registry.get_bytes(digest)
        except Exception as exc:
            raise OrchestrationError(
                "execution input binding cannot resolve a frozen input"
            ) from exc
        if (
            not isinstance(value, Mapping)
            or set(value) != {"kind", "sha256", "size", "staged_name"}
            or value.get("kind") != kind
            or value.get("sha256") != digest
            or value.get("size") != len(payload)
            or value.get("staged_name") != f"frozen-input-{kind}{suffix}"
        ):
            raise OrchestrationError(
                "execution input binding differs from the frozen spec"
            )


def _custody_access_records(journal_bytes: bytes) -> list[dict[str, Any]]:
    """Extract records only from provider-validated, held-fd journal bytes."""

    records: list[dict[str, Any]] = []
    for raw_line in journal_bytes.splitlines():
        event = safe_json_loads(raw_line)
        if not isinstance(event, Mapping):
            raise OrchestrationError("custody journal event is malformed")
        payload = event.get("payload")
        if event.get("event_type") in {"ACCESS", "RELEASE"}:
            if not isinstance(payload, Mapping) or not isinstance(
                payload.get("record"), Mapping
            ):
                raise OrchestrationError("custody access event is malformed")
            records.append(dict(payload["record"]))
    return records


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _custody_journal_path(run_id: str) -> Path:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise OrchestrationError("invalid run ID for custody authority")
    return Path(".scientist-one-build/custody") / f"{run_id}.jsonl"


@contextmanager
def _project_resource_execution_lock(
    root: Path,
    *,
    expected_root_identity: tuple[int, int] | None = None,
    nonblocking: bool = False,
) -> Iterator[None]:
    """Serialize work under a parent-namespace lock that survives root swaps."""

    if type(nonblocking) is not bool:
        raise OrchestrationError("nonblocking must be an exact boolean")
    flock_operation = fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0)
    owner_pid = os.getpid()
    lexical_root = Path(root)
    if not lexical_root.is_absolute():
        lexical_root = Path.cwd() / lexical_root
    root_name = lexical_root.name
    if root_name in {"", ".", ".."}:
        raise OrchestrationError("project resource namespace identity changed")
    try:
        root_parent = lexical_root.parent.resolve(strict=True)
    except OSError as exc:
        raise OrchestrationError("project resource execution lock failed") from exc
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    parent_fd = root_fd = descriptor = None
    parent_locked = leaf_locked = False
    try:
        parent_fd = os.open(root_parent, directory_flags)
        parent_identity = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent_identity.st_mode):
            raise OrchestrationError("project parent namespace is not a directory")
        fcntl.flock(parent_fd, flock_operation)
        parent_locked = True
        named_parent = os.stat(root_parent, follow_symlinks=False)
        if (parent_identity.st_dev, parent_identity.st_ino) != (
            named_parent.st_dev,
            named_parent.st_ino,
        ):
            raise OrchestrationError("project parent namespace identity changed")
        try:
            root_fd = os.open(root_name, directory_flags, dir_fd=parent_fd)
        except OSError as exc:
            raise OrchestrationError(
                "project resource namespace identity changed"
            ) from exc
        root_identity = os.fstat(root_fd)
        named_root = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
        observed_root_identity = (root_identity.st_dev, root_identity.st_ino)
        if (
            not stat.S_ISDIR(root_identity.st_mode)
            or observed_root_identity != (named_root.st_dev, named_root.st_ino)
            or (
                expected_root_identity is not None
                and observed_root_identity != expected_root_identity
            )
        ):
            raise OrchestrationError("project resource namespace identity changed")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(
            ".scientist-one-resource-execution.lock",
            flags,
            0o600,
            dir_fd=root_fd,
        )
        metadata = os.fstat(descriptor)
        named = os.stat(
            ".scientist-one-resource-execution.lock",
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_mode & 0o077) != 0
            or (metadata.st_dev, metadata.st_ino)
            != (named.st_dev, named.st_ino)
        ):
            raise OrchestrationError("project resource execution lock is invalid")
        fcntl.flock(descriptor, flock_operation)
        leaf_locked = True
        locked = os.fstat(descriptor)
        current = os.stat(
            ".scientist-one-resource-execution.lock",
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        if (locked.st_dev, locked.st_ino) != (current.st_dev, current.st_ino):
            raise OrchestrationError("project resource execution lock was replaced")
        try:
            yield
        finally:
            if nonblocking and os.getpid() != owner_pid:
                # A child shares flock's open-file descriptions with its
                # parent. Never validate or unlock the parent's live guard.
                raise OrchestrationError("inherited project resource guard cannot exit as owner")
            # Re-attest even when command execution raises.  Otherwise a root
            # replacement could escape the command-wide boundary on an error
            # path before the launcher's final provenance check.
            final_root = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
            final_lock = os.stat(
                ".scientist-one-resource-execution.lock",
                dir_fd=root_fd,
                follow_symlinks=False,
            )
            if (
                observed_root_identity != (final_root.st_dev, final_root.st_ino)
                or (locked.st_dev, locked.st_ino)
                != (final_lock.st_dev, final_lock.st_ino)
            ):
                raise OrchestrationError("project resource namespace changed")
    except OSError as exc:
        raise OrchestrationError("project resource execution lock failed") from exc
    finally:
        if descriptor is not None:
            if leaf_locked and (not nonblocking or os.getpid() == owner_pid):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        if root_fd is not None:
            os.close(root_fd)
        if parent_fd is not None:
            if parent_locked and (not nonblocking or os.getpid() == owner_pid):
                fcntl.flock(parent_fd, fcntl.LOCK_UN)
            os.close(parent_fd)


def _named_directory_identity(path: Path) -> tuple[int, int]:
    """Read a directory identity without following its final path component."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise OrchestrationError(
            "project root must be an existing non-symlink directory"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise OrchestrationError(
            "project root must be an existing non-symlink directory"
        )
    return opened.st_dev, opened.st_ino


def _read_resource_authority_records(
    root: Path,
    run_id: str,
) -> tuple[dict[str, Any], ...]:
    """Read the bounded external resource chain without trusting run-local state."""

    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise OrchestrationError("invalid run ID for resource authority")
    relative = Path(".scientist-one-build/resource-authority") / run_id
    _secure_directory(root, relative, create=False)
    try:
        directory_fd = open_confined_directory_fd(root, relative, create=False)
        try:
            names: list[str] = []
            with os.scandir(directory_fd) as iterator:
                for entry in iterator:
                    if not RESOURCE_AUTHORITY_NAME_PATTERN.fullmatch(entry.name):
                        raise OrchestrationError(
                            "resource authority contains an unknown entry"
                        )
                    if len(names) >= 16:
                        raise OrchestrationError(
                            "resource authority exceeds its bounded history"
                        )
                    names.append(entry.name)
        finally:
            os.close(directory_fd)
    except (OSError, PathSecurityError) as exc:
        raise OrchestrationError("resource authority directory is unsafe") from exc
    records: list[dict[str, Any]] = []
    prior_digest: str | None = None
    for expected_sequence, name in enumerate(sorted(names)):
        matched = RESOURCE_AUTHORITY_NAME_PATTERN.fullmatch(name)
        if matched is None or int(matched.group("sequence")) != expected_sequence:
            raise OrchestrationError("resource authority sequence is not contiguous")
        try:
            data = read_confined_bytes(
                root,
                relative / name,
                reject_hardlinks=True,
                max_bytes=1024 * 1024,
            )
            value = safe_json_loads(data) if data is not None else None
        except Exception as exc:
            raise OrchestrationError("resource authority record is unsafe") from exc
        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "kind",
            "run_id",
            "sequence",
            "logical_type",
            "state_sha256",
            "state",
            "prior_authority_sha256",
        }:
            raise OrchestrationError("resource authority record schema is invalid")
        digest = _sha256(data)
        state = value.get("state")
        if (
            digest != matched.group("digest")
            # Native publication hashes these exact bytes, including the LF.
            # Value-equivalent JSON cannot replace an existing external head:
            # descriptors and subsequent predecessor links use canonical bytes.
            or data != _canonical_bytes(value)
            or value.get("schema_version") != SCHEMA_VERSION
            or value.get("kind") != "RESOURCE_RUNTIME_AUTHORITY"
            or value.get("run_id") != run_id
            or type(value.get("sequence")) is not int
            or value.get("sequence") != expected_sequence
            or not isinstance(value.get("logical_type"), str)
            or not str(value["logical_type"]).startswith("resource_runtime_")
            or not isinstance(state, dict)
            or value.get("state_sha256") != _sha256(_canonical_bytes(state))
            or value.get("prior_authority_sha256") != prior_digest
        ):
            raise OrchestrationError("resource authority record binding is invalid")
        records.append(value)
        prior_digest = digest
    return tuple(records)


def _resource_authority_descriptors_for(
    records: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "sequence": index,
            "logical_type": record["logical_type"],
            "state_sha256": record["state_sha256"],
            "authority_sha256": _sha256(_canonical_bytes(record)),
            "prior_authority_sha256": record["prior_authority_sha256"],
        }
        for index, record in enumerate(records)
    ]


def _persist_resource_authority_for(
    root: Path,
    run_id: str,
    logical_type: str,
    state: Mapping[str, Any],
) -> dict[str, Any]:
    """Advance the native external head before run-local evidence.

    Callers retain the existing outer project-resource execution lock. This
    primitive owns storage/idempotency, not the scientific meaning of a stage.
    """

    if type(logical_type) is not str or not logical_type.startswith(
        "resource_runtime_"
    ):
        raise OrchestrationError("resource authority stage is invalid")
    records = _read_resource_authority_records(root, run_id)
    normalized_state = safe_json_loads(canonical_json_bytes(state))
    if not isinstance(normalized_state, dict):
        raise OrchestrationError("resource authority state must be an object")
    if records and records[-1]["logical_type"] == logical_type:
        if records[-1]["state"] != normalized_state:
            raise OrchestrationError("resource authority idempotency collision")
        return records[-1]
    if any(record["logical_type"] == logical_type for record in records):
        raise OrchestrationError("resource authority stage cannot be replayed")
    if len(records) >= 16:
        raise OrchestrationError("resource authority exceeds its bounded history")
    prior_digest = None
    if records:
        prior_digest = _sha256(_canonical_bytes(records[-1]))
    payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": "RESOURCE_RUNTIME_AUTHORITY",
        "run_id": run_id,
        "sequence": len(records),
        "logical_type": logical_type,
        "state_sha256": _sha256(_canonical_bytes(normalized_state)),
        "state": normalized_state,
        "prior_authority_sha256": prior_digest,
    }
    data = _canonical_bytes(payload)
    if len(data) > 1024 * 1024:
        raise OrchestrationError("resource authority exceeds its record byte bound")
    relative = (
        Path(".scientist-one-build/resource-authority")
        / run_id
        / f"{len(records):04d}-{_sha256(data)}.json"
    )
    try:
        atomic_write_bytes(
            root, relative, data, immutable=True, create_parents=True
        )
    except PathSecurityError as exc:
        raise OrchestrationError("resource authority advance failed") from exc
    persisted = _read_resource_authority_records(root, run_id)
    if len(persisted) != len(records) + 1 or persisted[-1] != payload:
        raise OrchestrationError("resource authority advance did not verify")
    return payload


def _validate_resource_authority_ledger_for(
    records: Sequence[Mapping[str, Any]],
    events: Sequence[Any],
) -> None:
    """Require every native resource checkpoint and exact STARTED repeat."""

    descriptors = _resource_authority_descriptors_for(records)
    observed: list[dict[str, Any]] = []
    repeated_confirmatory_sequences: set[int] = set()
    reconciled = False
    for event in events:
        if isinstance(event, Mapping):
            event_metadata = event.get("metadata", {})
            event_artifact_hashes = event.get("artifact_hashes", ())
            event_type = event.get("event_type")
            state_before = event.get("state_before")
            requested_state = event.get("requested_state_after")
        else:
            event_metadata = event.metadata
            event_artifact_hashes = event.artifact_hashes
            event_type = event.event_type
            state_before = event.state_before.value
            requested_state = event.requested_state_after.value
        if not isinstance(event_metadata, Mapping):
            raise OrchestrationError("resource ledger metadata is malformed")
        names = event_metadata.get("artifact_types", ())
        if not isinstance(names, (list, tuple)):
            raise OrchestrationError("resource ledger artifact types are malformed")
        resource_positions = [
            index
            for index, name in enumerate(names)
            if isinstance(name, str) and name.startswith("resource_runtime_")
        ]
        binding = event_metadata.get("resource_authority_checkpoint")
        if len(resource_positions) > 1:
            raise OrchestrationError("resource ledger event is ambiguous")
        if resource_positions:
            position = resource_positions[0]
            if position >= len(event_artifact_hashes):
                raise OrchestrationError("resource ledger artifact is unbound")
            scientific_repeat = (
                event_type == "CONFIRMATORY_STARTED"
                and event_metadata.get("evidence_class")
                != "ARCHITECTURE_CONTROL"
                and event_metadata.get("execution_kind")
                != "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
            )
            simulated_repeat = (
                event_type == "CHECKPOINT"
                and event_metadata.get("evidence_class")
                == "ARCHITECTURE_CONTROL"
                and event_metadata.get("execution_kind")
                == "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
            )
            repeat_state_is_valid = (
                scientific_repeat
                and state_before == "CONFIRM"
                and requested_state == "CONFIRM"
            ) or (
                simulated_repeat
                and state_before == requested_state
                and state_before in {state.value for state in MacroState}
            )
            repeated = (
                (scientific_repeat or simulated_repeat)
                and repeat_state_is_valid
                and bool(observed)
                and binding == observed[-1]
                and names[position] == observed[-1]["logical_type"]
                and event_artifact_hashes[position]
                == observed[-1]["state_sha256"]
            )
            if (scientific_repeat or simulated_repeat) and not repeated:
                raise OrchestrationError(
                    "reveal resource authority must repeat the immediately "
                    "preceding checkpoint with its exact execution class"
                )
            if repeated:
                sequence = int(observed[-1]["sequence"])
                if sequence in repeated_confirmatory_sequences:
                    raise OrchestrationError(
                        "confirmatory resource authority was repeated more than once"
                    )
                repeated_confirmatory_sequences.add(sequence)
            else:
                if len(observed) >= len(descriptors):
                    raise OrchestrationError("resource ledger has an extra checkpoint")
                expected = descriptors[len(observed)]
                if (
                    binding != expected
                    or names[position] != expected["logical_type"]
                    or event_artifact_hashes[position] != expected["state_sha256"]
                ):
                    raise OrchestrationError(
                        "resource authority history differs from its ledger commitment"
                    )
                observed.append(expected)
        elif binding is not None:
            raise OrchestrationError(
                "resource authority binding lacks a checkpoint artifact"
            )
        reconciliation = event_metadata.get("resource_authority_chain")
        if reconciliation is not None:
            if (
                reconciled
                or event_type != "SECURITY_STOP"
                or requested_state != "STOP_SECURITY"
                or not isinstance(reconciliation, (list, tuple))
                or tuple(reconciliation) != tuple(descriptors)
            ):
                raise OrchestrationError(
                    "resource rollback reconciliation is malformed"
                )
            reconciled = True
    if observed != descriptors and not reconciled:
        raise OrchestrationError(
            "external resource authority is not fully ledger-bound"
        )


def _runtime_state_from_authority_record(
    record: Mapping[str, Any],
) -> ResourceRuntimeState:
    state = record.get("state")
    if not isinstance(state, Mapping):
        raise OrchestrationError("resource authority state is malformed")
    if record.get("logical_type") == RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE:
        if set(state) != {
            "schema_version",
            "kind",
            "run_id",
            "frozen_configuration_inventory_artifact_sha256",
            "frozen_configuration_inventory_record_hash",
            "resource_config",
            "resource_config_sha256",
            "runtime_state",
            "prior_resource_runtime_artifact_sha256",
            "authority_scope",
            "scientific_evidence",
        } or state.get("schema_version") != RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_SCHEMA:
            raise OrchestrationError("wall-budget observation payload is malformed")
        runtime = state.get("runtime_state")
    elif record.get("logical_type") == RESOURCE_RUNTIME_PILOT_FAILURE:
        if (set(state) != _PILOT_FAILURE_FIELDS
                or state.get("schema_version") != _PILOT_FAILURE_SCHEMA
                or state.get("kind") != "PILOT_CALL_FAILURE"
                or state.get("authority_scope") != "OPERATIONAL_STICKY_BLOCK"
                or state.get("scientific_evidence") is not False
                or state.get("retry_allowed") is not False):
            raise OrchestrationError("pilot failure wrapper is malformed")
        runtime = state["runtime_state"]
    elif record.get("logical_type") == RESOURCE_RUNTIME_ADMISSION_REFUSAL:
        if (set(state) != _RESOURCE_ADMISSION_FIELDS
                or state.get("schema_version") != _RESOURCE_ADMISSION_SCHEMA
                or state.get("kind") != "RESOURCE_ADMISSION_REFUSAL"
                or state.get("authority_scope") != "OPERATIONAL_STICKY_BLOCK"
                or state.get("scientific_evidence") is not False
                or not isinstance(state.get("observation"), Mapping)
                or set(state["observation"]) != {
                    "request", "time_context", "decision", "runtime_state"}):
            raise OrchestrationError("resource admission wrapper is malformed")
        runtime = state["observation"]["runtime_state"]
    else:
        runtime = state
    try:
        return ResourceRuntimeState.from_mapping(runtime)  # type: ignore[arg-type]
    except Exception as exc:
        raise OrchestrationError("resource runtime authority state is invalid") from exc


def _validate_monotonic_resource_states(
    records: Sequence[Mapping[str, Any]],
) -> tuple[ResourceRuntimeState, ...]:
    states = tuple(_runtime_state_from_authority_record(record) for record in records)
    return _validate_monotonic_runtime_states(states)


def _validate_monotonic_runtime_states(
    states: Sequence[ResourceRuntimeState],
) -> tuple[ResourceRuntimeState, ...]:
    states = tuple(states)
    if not states:
        raise OrchestrationError("resource runtime authority is absent")
    first = states[0]
    prior = first
    for state in states:
        if (
            state.run_id != first.run_id
            or state.config_sha256 != first.config_sha256
            or state.validity_total_units != first.validity_total_units
            # The controller pins the earliest effective epoch start when its
            # monotonic clock runs ahead.  A later start would replenish the
            # run's elapsed wall budget; tolerate only DTO-level float noise.
            or state.wall_started_at_epoch_seconds
            > prior.wall_started_at_epoch_seconds + 1e-6
            or state.wall_elapsed_seconds < prior.wall_elapsed_seconds
            or state.wall_observed_at_epoch_seconds
            < prior.wall_observed_at_epoch_seconds
            or state.checkpoint_elapsed_seconds < prior.checkpoint_elapsed_seconds
            or state.progress_elapsed_seconds < prior.progress_elapsed_seconds
            or state.exploratory_used < prior.exploratory_used
            or state.confirmatory_used < prior.confirmatory_used
            or any(
                state.worker_crashes.get(worker, -1) < count
                for worker, count in prior.worker_crashes.items()
            )
        ):
            raise OrchestrationError("resource runtime authority is not monotonic")
        prior = state
    return states


def _safe_root(
    root: str | os.PathLike[str],
    *,
    captured_root: tuple[Path, tuple[int, int]] | None = None,
) -> Path:
    path = Path(root)
    candidate = path if path.is_absolute() else Path.cwd() / path
    admitted_identity = _named_directory_identity(candidate)
    if captured_root is not None and admitted_identity != captured_root[1]:
        raise OrchestrationError("project root differs from the captured launcher root")
    canonical = candidate.resolve(strict=True)
    if captured_root is not None and canonical != captured_root[0]:
        raise OrchestrationError("project root differs from the captured launcher root")
    forbidden = {Path(canonical.anchor), Path.home().resolve(), Path.home().resolve() / "dev"}
    if canonical in forbidden or canonical.name != "ScientistOne":
        raise OrchestrationError("project root is not the narrow ScientistOne workspace")
    try:
        current = Path.cwd().resolve(strict=True)
    except OSError as exc:
        raise OrchestrationError("current app workspace cannot be canonicalized") from exc
    if canonical != current:
        raise OrchestrationError("--root must equal the current app-selected workspace")
    if _named_directory_identity(canonical) != admitted_identity:
        raise OrchestrationError("project root identity changed during admission")
    try:
        receipt_bytes = read_confined_bytes(
            canonical,
            "state/APP_SESSION_BOOTSTRAP.json",
            reject_hardlinks=True,
            max_bytes=1024 * 1024,
        )
        if receipt_bytes is None:
            raise OrchestrationError("passing app-session bootstrap receipt is required")
        receipt = safe_json_loads(receipt_bytes)
    except (OSError, ValueError, PathSecurityError) as exc:
        raise OrchestrationError("app-session bootstrap receipt is invalid") from exc
    if not isinstance(receipt, dict) or receipt.get("app_session_bootstrap") != "PASS":
        raise OrchestrationError("app-session bootstrap did not pass")
    if receipt.get("canonical_project_root") != str(canonical):
        raise OrchestrationError("bootstrap receipt does not bind the current workspace")
    if _named_directory_identity(canonical) != admitted_identity:
        raise OrchestrationError("project root identity changed during admission")
    return canonical


def _secure_directory(root: Path, relative: str | Path, *, create: bool = False) -> Path:
    raw = Path(relative)
    if raw.is_absolute() or any(part in {"", ".", ".."} for part in raw.parts):
        raise OrchestrationError("directory path must be a safe project-relative path")
    try:
        return secure_directory_shared(root, raw, create=create)
    except PathSecurityError as exc:
        raise OrchestrationError(f"unsafe project directory: {raw}") from exc


def _safe_existing_file(root: Path, value: str | Path) -> Path:
    raw = Path(value)
    if any(part == ".." for part in raw.parts):
        raise OrchestrationError("path traversal is prohibited")
    candidate = raw if raw.is_absolute() else root / raw
    try:
        relative = candidate.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise OrchestrationError("input file is outside project root or absent") from exc
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise OrchestrationError("symbolic links are prohibited for evidence inputs")
    mode = candidate.lstat().st_mode
    if not stat.S_ISREG(mode) or candidate.stat().st_nlink != 1:
        raise OrchestrationError("evidence input must be an unlinked regular file")
    return candidate.resolve(strict=True)


def _atomic_json(root: Path, relative: str | Path, value: Mapping[str, Any]) -> Path:
    try:
        return atomic_write_json(
            root,
            relative,
            value,
            overwrite=True,
            create_parents=True,
        )
    except (PathSecurityError, ValueError, TypeError) as exc:
        raise OrchestrationError("confined atomic JSON publication failed") from exc


def _read_json(path: Path) -> dict[str, Any]:
    try:
        root = Path.cwd().resolve(strict=True)
        payload = read_confined_bytes(
            root,
            path,
            reject_hardlinks=True,
            max_bytes=16 * 1024 * 1024,
        )
        if payload is None:
            raise OrchestrationError(f"JSON evidence disappeared: {path.name}")
        value = safe_json_loads(payload)
    except (OSError, ValueError, UnicodeDecodeError, PathSecurityError) as exc:
        raise OrchestrationError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise OrchestrationError(f"expected JSON object in {path.name}")
    return value


def _project_command(method: Callable[..., Any]) -> Callable[..., Any]:
    """Hold the admitted project-root namespace for one public command."""

    @wraps(method)
    def guarded(self: "ScientistOneOrchestrator", *args: Any, **kwargs: Any) -> Any:
        with self._command_root_guard():
            return method(self, *args, **kwargs)

    return guarded


def _code_fingerprint(root: Path) -> str:
    return str(_source_inventory(root)["aggregate_sha256"])


def _configuration_hash(root: Path) -> str:
    return str(_configuration_inventory(root)["aggregate_sha256"])


def _frozen_inventory(root: Path, directory: str, suffix: str, kind: str) -> dict[str, Any]:
    """Build one bounded, descriptor-read inventory used across every later gate."""

    entries: list[dict[str, Any]] = []
    try:
        directory_fd = open_confined_directory_fd(root, directory, create=False)
    except PathSecurityError as exc:
        raise OrchestrationError(f"unsafe {kind.lower()} inventory directory") from exc
    try:
        collected: list[str] = []
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                if entry.name.endswith(suffix):
                    if len(collected) >= MAX_INVENTORY_ENTRIES:
                        raise OrchestrationError(
                            f"{kind.lower()} inventory has too many entries"
                        )
                    collected.append(entry.name)
        names = tuple(sorted(collected))
        aggregate_bytes = 0
        for name in names:
            if not name or "/" in name or "\x00" in name:
                raise OrchestrationError(f"unsafe {kind.lower()} inventory name")
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
                    raise OrchestrationError(
                        f"unsafe {kind.lower()} inventory entry"
                    )
                chunks: list[bytes] = []
                total = 0
                while chunk := os.read(descriptor, 1024 * 1024):
                    total += len(chunk)
                    if total > 4 * 1024 * 1024:
                        raise OrchestrationError(
                            f"oversized {kind.lower()} inventory entry"
                        )
                    chunks.append(chunk)
                data = b"".join(chunks)
                aggregate_bytes += len(data)
                if aggregate_bytes > MAX_INVENTORY_TOTAL_BYTES:
                    raise OrchestrationError(
                        f"{kind.lower()} inventory exceeds its aggregate bound"
                    )
            finally:
                os.close(descriptor)
            entries.append(
                {
                    "path": (Path(directory) / name).as_posix(),
                    "sha256": _sha256(data),
                    "size": len(data),
                }
            )
    except OSError as exc:
        raise OrchestrationError(f"cannot enumerate {kind.lower()} inventory") from exc
    finally:
        os.close(directory_fd)
    if not entries:
        raise OrchestrationError(f"{kind.lower()} inventory is empty")
    aggregate = _sha256(_canonical_bytes(entries))
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "entries": entries,
        "aggregate_sha256": aggregate,
    }


def _source_inventory(root: Path) -> dict[str, Any]:
    inventory = _frozen_inventory(
        root, "src/scientist_one", ".py", "FROZEN_SOURCE_INVENTORY"
    )
    launcher = read_confined_bytes(
        root,
        "scripts/scientist_one_cli.py",
        reject_hardlinks=True,
        max_bytes=4 * 1024 * 1024,
    )
    if launcher is None:
        raise OrchestrationError("isolated CLI launcher is absent")
    entries = list(inventory["entries"])
    entries.append(
        {
            "path": "scripts/scientist_one_cli.py",
            "sha256": _sha256(launcher),
            "size": len(launcher),
        }
    )
    entries.sort(key=lambda value: str(value["path"]))
    if len(entries) > MAX_INVENTORY_ENTRIES:
        raise OrchestrationError("source inventory exceeds its entry bound")
    if sum(int(value["size"]) for value in entries) > MAX_INVENTORY_TOTAL_BYTES:
        raise OrchestrationError("source inventory exceeds its aggregate bound")
    inventory["entries"] = entries
    inventory["aggregate_sha256"] = _sha256(_canonical_bytes(entries))
    _validate_captured_source_attestation(root, inventory)
    return inventory


def _research_os_fixture_command_context(
    run_id: str | None,
    restart_from_run_id: str | None = None,
) -> tuple[str, ...]:
    command = (
        "python3",
        "-I",
        "-S",
        "-B",
        "scripts/scientist_one_cli.py",
        "research-os-fixture",
    )
    if run_id is not None:
        command += ("--run-id", run_id)
    if restart_from_run_id is not None:
        command += ("--restart-from", restart_from_run_id)
    return command


def _consume_guarded_launch_capability(
    capability: object,
    *,
    root: Path,
    run_id: str,
    created_at: str,
) -> dict[str, Any]:
    """Consume a production-only capability into an operational launch receipt."""

    if type(capability) is not _GuardedLaunchCapability:
        raise OrchestrationError("guarded launch capability type is invalid")
    guarded = capability
    if guarded._seal is not _GUARDED_LAUNCH_SEAL or guarded._consumed:
        raise OrchestrationError("guarded launch capability is invalid or already used")
    # Burn the capability before any fallible re-attestation so a failed launch
    # attempt can never be retried with the same operational authority.
    guarded._consumed = True
    owner = guarded._owner
    if not isinstance(owner, ScientistOneOrchestrator):
        raise OrchestrationError("guarded launch capability owner is invalid")
    if owner._command_guard_depth() <= 0:
        raise OrchestrationError("guarded launch capability is outside its command guard")
    if getattr(sys, "_scientist_one_isolated_launcher", False) is not True:
        raise OrchestrationError("guarded launch requires production captured dispatch")
    if "_scientist_one_captured_evidence_capability" in sys.__dict__:
        raise OrchestrationError("evidence dispatch cannot mint production launch authority")
    captured_root = _captured_project_root()
    if captured_root is None:
        raise OrchestrationError("captured production project root is unavailable")
    if (
        root != guarded._root
        or root != owner.root
        or captured_root[0] != root
        or guarded._root_identity != owner._root_identity
        or captured_root[1] != guarded._root_identity
        or _named_directory_identity(root) != guarded._root_identity
    ):
        raise OrchestrationError("guarded launch capability root binding is invalid")
    if guarded._requested_run_id is not None and guarded._requested_run_id != run_id:
        raise OrchestrationError("guarded launch capability run binding is invalid")
    if (
        guarded._restart_from_run_id is not None
        and (
            guarded._requested_run_id is None
            or guarded._restart_from_run_id == run_id
        )
    ):
        raise OrchestrationError("guarded restart run binding is invalid")
    expected_command = _research_os_fixture_command_context(
        guarded._requested_run_id,
        guarded._restart_from_run_id,
    )
    if (
        guarded._command_context != expected_command
        or owner.command_context != expected_command
    ):
        raise OrchestrationError("guarded launch capability command binding is invalid")
    source_inventory = _source_inventory(root)
    source_inventory_bytes = _canonical_bytes(source_inventory)
    if source_inventory_bytes != guarded._source_inventory_bytes:
        raise OrchestrationError("guarded launch capability source binding changed")
    if not isinstance(created_at, str) or not created_at.endswith("Z"):
        raise OrchestrationError("guarded launch capability timestamp is invalid")
    return {
        "canonical_project_root": str(root),
        "captured_source_inventory": source_inventory,
        "command_context": list(expected_command),
        "created_at": created_at,
        "launch_mode": VNEXT_GUARDED_LAUNCH_MODE,
        "root_identity": {
            "device": guarded._root_identity[0],
            "inode": guarded._root_identity[1],
        },
        "run_id": run_id,
        "schema_version": VNEXT_GUARDED_LAUNCH_SCHEMA_VERSION,
        "scientific_authority": False,
    }


def _consume_guarded_restart_lineage(
    capability: object,
    *,
    root: Path,
    run_id: str,
    restart_from_run_id: str | None,
    created_at: str,
) -> dict[str, Any] | None:
    """Consume the restart-only part of an already burned launch capability."""

    if type(capability) is not _GuardedLaunchCapability:
        raise OrchestrationError("guarded restart capability type is invalid")
    guarded = capability
    if (
        guarded._seal is not _GUARDED_LAUNCH_SEAL
        or not guarded._consumed
        or guarded._restart_lineage_consumed
    ):
        raise OrchestrationError("guarded restart capability is invalid or already used")
    guarded._restart_lineage_consumed = True
    if guarded._restart_from_run_id is None:
        if (
            restart_from_run_id is not None
            or guarded._restart_source_operation_sha256 is not None
            or guarded._restart_source_operation_schema_version is not None
            or guarded._restart_source_guarded_receipt_sha256 is not None
        ):
            raise OrchestrationError("guarded non-restart capability has restart state")
        return None
    if (
        restart_from_run_id != guarded._restart_from_run_id
        or guarded._requested_run_id != run_id
        or restart_from_run_id == run_id
        or root != guarded._root
    ):
        raise OrchestrationError("guarded restart lineage binding is invalid")
    owner = guarded._owner
    if not isinstance(owner, ScientistOneOrchestrator):
        raise OrchestrationError("guarded restart capability owner is invalid")
    operation = owner._fixture_operation_receipt(
        restart_from_run_id,
        required=True,
    )
    source_schema_version = guarded._restart_source_operation_schema_version
    if (
        operation is None
        or operation.get("schema_version")
        not in {
            VNEXT_OPERATION_SCHEMA_VERSION,
            VNEXT_RESTART_OPERATION_SCHEMA_VERSION,
        }
        or operation.get("schema_version") != source_schema_version
        or operation.get("status") != "IN_PROGRESS"
        or operation.get("launch_mode") != VNEXT_GUARDED_LAUNCH_MODE
        or operation.get("recovery_policy")
        != VNEXT_OPERATION_STATUS_POLICY["IN_PROGRESS"]
    ):
        raise OrchestrationError(
            "guarded restart source is not an abandoned production operation"
        )
    owner._guarded_launch_receipt(restart_from_run_id, operation)
    if source_schema_version == VNEXT_RESTART_OPERATION_SCHEMA_VERSION:
        owner._restart_lineage_receipt(restart_from_run_id, operation)
    operation_raw = read_confined_bytes(
        root,
        Path("runs") / restart_from_run_id / "fixture-operation.json",
        reject_hardlinks=True,
        max_bytes=1024 * 1024,
    )
    if operation_raw is None:
        raise OrchestrationError("guarded restart source operation disappeared")
    operation_sha256 = _sha256(operation_raw)
    guarded_sha256 = operation.get("guarded_launch_receipt_sha256")
    if (
        operation_sha256 != guarded._restart_source_operation_sha256
        or guarded_sha256
        != guarded._restart_source_guarded_receipt_sha256
    ):
        raise OrchestrationError("guarded restart source changed after admission")
    return {
        "abandoned_guarded_launch_receipt_sha256": guarded_sha256,
        "abandoned_launch_mode": VNEXT_GUARDED_LAUNCH_MODE,
        "abandoned_operation_sha256": operation_sha256,
        "abandoned_operation_schema_version": source_schema_version,
        "abandoned_operation_status": "IN_PROGRESS",
        "abandoned_resume_supported": False,
        "abandoned_run_id": restart_from_run_id,
        "canonical_project_root": str(root),
        "created_at": created_at,
        "kind": "GUARDED_NEW_RUN_RESTART_LINEAGE",
        "new_run_id": run_id,
        "protected_resources_reused": False,
        "recovery_semantics": "NEW_RUN_NO_SAME_ID_RESUME",
        "schema_version": VNEXT_RESTART_LINEAGE_SCHEMA_VERSION,
        "scientific_authority": False,
    }


def _configuration_inventory(root: Path) -> dict[str, Any]:
    return _frozen_inventory(
        root, "configs", ".json", "FROZEN_CONFIGURATION_INVENTORY"
    )


def _validate_captured_source_attestation(
    root: Path, source_inventory: Mapping[str, Any]
) -> None:
    """Bind evidence bytes to the exact sources executed by the safe launcher."""

    loader = _captured_dispatch_loader()
    raw_attestation = getattr(
        sys, "_scientist_one_captured_source_attestation", None
    )
    if loader is None:
        if raw_attestation is not None:
            raise OrchestrationError(
                "captured source attestation exists outside verified dispatch"
            )
        return
    if (
        not isinstance(raw_attestation, tuple)
        or len(raw_attestation) != 2
        or raw_attestation[0] != "SCIENTIST_ONE_CAPTURED_SOURCE_V1"
        or not isinstance(raw_attestation[1], tuple)
    ):
        raise OrchestrationError("captured source attestation is absent or malformed")
    raw_entries = raw_attestation[1]
    if not raw_entries or len(raw_entries) > MAX_INVENTORY_ENTRIES:
        raise OrchestrationError("captured source attestation exceeds its entry bound")
    inventory_entries = source_inventory.get("entries")
    if not isinstance(inventory_entries, list):
        raise OrchestrationError("source inventory entries are malformed")
    expected: dict[str, tuple[str, int]] = {}
    for value in inventory_entries:
        if (
            not isinstance(value, Mapping)
            or set(value) != {"path", "sha256", "size"}
            or not isinstance(value.get("path"), str)
            or not isinstance(value.get("sha256"), str)
            or isinstance(value.get("size"), bool)
            or not isinstance(value.get("size"), int)
        ):
            raise OrchestrationError("source inventory entry is malformed")
        expected[str(value["path"])] = (str(value["sha256"]), int(value["size"]))
    if len(expected) != len(inventory_entries):
        raise OrchestrationError("source inventory contains duplicate paths")

    observed_paths: list[str] = []
    observed_total = 0
    for entry in raw_entries:
        if not isinstance(entry, tuple) or len(entry) != 7:
            raise OrchestrationError("captured source entry is malformed")
        relative, digest, size, device, inode, modified_ns, changed_ns = entry
        if (
            not isinstance(relative, str)
            or not relative
            or Path(relative).is_absolute()
            or any(part in {"", ".", ".."} for part in Path(relative).parts)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or any(
                isinstance(item, bool) or not isinstance(item, int) or item < 0
                for item in (size, device, inode, modified_ns, changed_ns)
            )
            or size > 4 * 1024 * 1024
        ):
            raise OrchestrationError("captured source entry has invalid fields")
        observed_total += size
        if observed_total > MAX_INVENTORY_TOTAL_BYTES:
            raise OrchestrationError(
                "captured source attestation exceeds its aggregate bound"
            )
        observed_paths.append(relative)
        if expected.get(relative) != (digest, size):
            raise OrchestrationError(
                "captured source bytes differ from the frozen source inventory"
            )
        directory_fd = descriptor = None
        try:
            directory_fd = open_confined_directory_fd(
                root, Path(relative).parent, create=False
            )
            descriptor = os.open(
                Path(relative).name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            before = os.fstat(descriptor)
            named = os.stat(
                Path(relative).name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
                or (
                    before.st_dev,
                    before.st_ino,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                != (device, inode, modified_ns, changed_ns)
                or before.st_size != size
            ):
                raise OrchestrationError(
                    "captured source identity changed before evidence binding"
                )
            chunks: list[bytes] = []
            total = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                total += len(chunk)
                if total > 4 * 1024 * 1024:
                    raise OrchestrationError("captured source exceeds its size bound")
                chunks.append(chunk)
            after = os.fstat(descriptor)
            if (
                (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                )
                or total != size
                or _sha256(b"".join(chunks)) != digest
            ):
                raise OrchestrationError(
                    "captured source bytes changed before evidence binding"
                )
        except (OSError, PathSecurityError) as exc:
            raise OrchestrationError(
                "captured source cannot be revalidated safely"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory_fd is not None:
                os.close(directory_fd)
    if observed_paths != sorted(observed_paths) or len(set(observed_paths)) != len(
        observed_paths
    ):
        raise OrchestrationError("captured source attestation is unordered or ambiguous")
    if set(observed_paths) != set(expected):
        raise OrchestrationError(
            "captured source attestation does not cover the source inventory"
        )


def _validate_loaded_project_modules(
    root: Path, source_inventory: Mapping[str, Any]
) -> None:
    """Reject project-local import shadowing and loaded-source drift."""

    _validate_captured_source_attestation(root, source_inventory)
    expected = {
        str(entry["path"]): str(entry["sha256"])
        for entry in source_inventory.get("entries", ())
        if isinstance(entry, Mapping)
    }
    for module_name, module in tuple(sys.modules.items()):
        raw_file = getattr(module, "__file__", None)
        if not isinstance(raw_file, str):
            continue
        try:
            candidate = Path(raw_file).resolve(strict=True)
            relative = candidate.relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        if module_name == "__main__":
            continue
        if getattr(sys, "_scientist_one_test_runner", False) is True:
            try:
                candidate.relative_to(root / "tests")
                info = candidate.stat()
            except (OSError, ValueError):
                pass
            else:
                if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    continue
        if not module_name.startswith("scientist_one"):
            raise OrchestrationError(
                f"project-local module shadowing is forbidden: {module_name}"
            )
        if candidate.suffix != ".py" or relative not in expected:
            raise OrchestrationError(
                f"loaded Scientist-One module is outside the source inventory: {module_name}"
            )
        data = read_confined_bytes(
            root, relative, reject_hardlinks=True, max_bytes=4 * 1024 * 1024
        )
        if data is None or _sha256(data) != expected[relative]:
            raise OrchestrationError(
                f"loaded Scientist-One module differs from its source inventory: {module_name}"
            )


def _synthetic_study(run_id: str) -> Any:
    """Construct the one typed study whose canonical payload is persisted."""

    conditions = ExecutionConditions(
        "identity-v1",
        "frozen role-specific fixtures",
        1,
        "not applicable; deterministic bounded pass",
        120.0,
        "synthetic scalar outcome",
        True,
    )
    protocol = ResearchProtocol(
        study_id=f"{run_id}-study-v1",
        study_version=1,
        primary_hypothesis="the treatment fixture mean exceeds control by exactly 1.0",
        primary_estimand="treatment_mean_minus_control_mean",
        primary_metric="arithmetic_mean_difference",
        secondary_metrics=("six_scenario_known_answer_accuracy",),
        unit_of_analysis="synthetic_unit_id",
        resampling_unit="synthetic_unit_id",
        data_exclusions=(),
        data_roles=DataRoles(
            ("train-fixture-v1",),
            ("workflow-development-v1",),
            ("workflow-validation-v1",),
            ("synthetic-confirmatory-v1",),
        ),
        candidate_conditions=conditions,
        baseline_set=(BaselineSpec("known-answer-contract-v1", conditions),),
        ablation_set=("trap_detection_by_scenario",),
        negative_controls=("true_null",),
        domain_nulls=(
            DomainNullSpec(
                "paired-synthetic-unit-null",
                "paired unit-respecting sign reversal",
                "synthetic_unit_id",
                ("paired unit",),
                ("paired units are exchangeable under the null",),
                True,
            ),
        ),
        statistical_tests=(
            StatisticalTestSpec(
                "primary-difference",
                "deterministic difference of arithmetic means",
                "paired-synthetic-unit-null",
                "greater",
            ),
        ),
        confidence_intervals=(
            ConfidenceIntervalSpec("unit bootstrap", 0.95, "synthetic_unit_id"),
        ),
        multiple_comparison_correction="Holm across primary and secondary metrics",
        seed_policy=SeedPolicy(
            (20260812,), "single frozen seed", "mechanical execution failure only"
        ),
        compute_budget=ProtocolComputeBudget(1, 120.0, 1, 1),
        stopping_rules=("stop on any mandatory gate failure",),
        decision_ladder=(
            "positive",
            "negative",
            "inconclusive",
            "scientific invalidity",
        ),
        claim_scope_contract="claims apply only to deterministic synthetic workflow behavior",
        interpretation_rules=InterpretationRules(
            "bounded positive synthetic claim",
            "NEGATIVE_RESULT",
            "INCONCLUSIVE",
            "STOP_SCIENTIFIC_INVALIDITY",
        ),
        validity_reserve_fraction=0.40,
        reserve_basis="data_and_compute",
    )
    validate_protocol(protocol)
    return freeze_protocol(protocol)


class ScientistOneOrchestrator:
    """A local controller that advances only through typed evidence contracts."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        captured_root = _captured_project_root()
        self.root = _safe_root(root, captured_root=captured_root)
        self._root_identity = _named_directory_identity(self.root)
        self._command_thread_lock = threading.RLock()
        self._command_guard_state = threading.local()
        with _project_resource_execution_lock(
            self.root, expected_root_identity=self._root_identity
        ):
            for directory in (
                "runs", "artifacts", "reports", "state",
                ".scientist-one-build/checkpoints", ".scientist-one-build/tmp",
                ".scientist-one-build/custody",
                ".scientist-one-build/resource-authority",
            ):
                _secure_directory(self.root, directory, create=True)
            if captured_root is not None:
                # Every supported command crosses the captured-byte provenance
                # gate before it can inspect or mutate run state. start() repeats
                # this immediately before freezing its source inventory.
                _source_inventory(self.root)
        self.command_context: tuple[str, ...] = (
            "python3", "-I", "-S", "-B", "scripts/scientist_one_cli.py", "internal"
        )

    def set_command_context(self, argv: Sequence[str]) -> None:
        if not argv or any(not isinstance(item, str) or not item or "\x00" in item for item in argv):
            raise OrchestrationError("invalid command provenance")
        self.command_context = tuple(argv)

    def _mint_guarded_launch_capability(
        self,
        run_id: str | None,
        *,
        restart_from_run_id: str | None = None,
    ) -> _GuardedLaunchCapability:
        """Mint launch provenance only inside the active captured production command."""

        if self._command_guard_depth() <= 0:
            raise OrchestrationError("guarded launch requires an active command guard")
        if getattr(sys, "_scientist_one_isolated_launcher", False) is not True:
            raise OrchestrationError("guarded launch requires production captured dispatch")
        if "_scientist_one_captured_evidence_capability" in sys.__dict__:
            raise OrchestrationError("evidence dispatch cannot mint production launch authority")
        loader = _captured_dispatch_loader()
        captured_root = _captured_project_root()
        if loader is None or captured_root is None:
            raise OrchestrationError("captured production launch authority is unavailable")
        if (
            captured_root[0] != self.root
            or captured_root[1] != self._root_identity
            or _named_directory_identity(self.root) != self._root_identity
        ):
            raise OrchestrationError("captured production root binding is invalid")
        if run_id is not None and RUN_ID_PATTERN.fullmatch(run_id) is None:
            raise OrchestrationError("invalid research-os fixture run ID")
        restart_source_operation_sha256: str | None = None
        restart_source_operation_schema_version: str | None = None
        restart_source_guarded_receipt_sha256: str | None = None
        if restart_from_run_id is not None:
            if (
                run_id is None
                or RUN_ID_PATTERN.fullmatch(restart_from_run_id) is None
                or restart_from_run_id == run_id
            ):
                raise OrchestrationError(
                    "guarded restart requires distinct explicit run IDs"
                )
            restart_operation = self._fixture_operation_receipt(
                restart_from_run_id,
                required=True,
            )
            if (
                restart_operation is None
                or restart_operation.get("schema_version")
                not in {
                    VNEXT_OPERATION_SCHEMA_VERSION,
                    VNEXT_RESTART_OPERATION_SCHEMA_VERSION,
                }
                or restart_operation.get("status") != "IN_PROGRESS"
                or restart_operation.get("launch_mode")
                != VNEXT_GUARDED_LAUNCH_MODE
                or restart_operation.get("recovery_policy")
                != VNEXT_OPERATION_STATUS_POLICY["IN_PROGRESS"]
            ):
                raise OrchestrationError(
                    "guarded restart source is not an abandoned production operation"
                )
            self._guarded_launch_receipt(
                restart_from_run_id,
                restart_operation,
            )
            if (
                restart_operation.get("schema_version")
                == VNEXT_RESTART_OPERATION_SCHEMA_VERSION
            ):
                self._restart_lineage_receipt(
                    restart_from_run_id,
                    restart_operation,
                )
            restart_operation_raw = read_confined_bytes(
                self.root,
                Path("runs")
                / restart_from_run_id
                / "fixture-operation.json",
                reject_hardlinks=True,
                max_bytes=1024 * 1024,
            )
            if restart_operation_raw is None:
                raise OrchestrationError(
                    "guarded restart source operation disappeared"
                )
            restart_source_operation_sha256 = _sha256(
                restart_operation_raw
            )
            restart_source_operation_schema_version = str(
                restart_operation["schema_version"]
            )
            restart_source_guarded_receipt_sha256 = str(
                restart_operation["guarded_launch_receipt_sha256"]
            )
        expected_command = _research_os_fixture_command_context(
            run_id,
            restart_from_run_id,
        )
        if self.command_context != expected_command:
            raise OrchestrationError("guarded production command context is invalid")
        source_inventory = _source_inventory(self.root)
        return _GuardedLaunchCapability(
            seal=_GUARDED_LAUNCH_SEAL,
            owner=self,
            root=self.root,
            root_identity=self._root_identity,
            requested_run_id=run_id,
            restart_from_run_id=restart_from_run_id,
            restart_source_operation_sha256=(
                restart_source_operation_sha256
            ),
            restart_source_operation_schema_version=(
                restart_source_operation_schema_version
            ),
            restart_source_guarded_receipt_sha256=(
                restart_source_guarded_receipt_sha256
            ),
            command_context=expected_command,
            source_inventory_bytes=_canonical_bytes(source_inventory),
        )

    def _assert_project_root_identity(self) -> None:
        if _named_directory_identity(self.root) != self._root_identity:
            raise OrchestrationError("project root identity changed after admission")

    def _command_guard_depth(self) -> int:
        depth = getattr(self._command_guard_state, "depth", 0)
        if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
            raise OrchestrationError("project command guard state is invalid")
        return depth

    @contextmanager
    def _command_root_guard(self) -> Iterator[None]:
        """Serialize a complete command under its admitted root identity."""

        with self._command_thread_lock:
            depth = self._command_guard_depth()
            if depth:
                self._assert_project_root_identity()
                self._command_guard_state.depth = depth + 1
                try:
                    yield
                finally:
                    self._command_guard_state.depth = depth
                return
            with _project_resource_execution_lock(
                self.root, expected_root_identity=self._root_identity
            ):
                self._command_guard_state.depth = 1
                try:
                    yield
                finally:
                    self._command_guard_state.depth = 0

    def _run_dir(self, run_id: str, *, create: bool = False) -> Path:
        if not RUN_ID_PATTERN.fullmatch(run_id):
            raise OrchestrationError("invalid run ID")
        return _secure_directory(self.root, Path("runs") / run_id, create=create)

    def _registry(self, run_id: str) -> ArtifactRegistry:
        """Return the run-scoped content store used by every run artifact.

        Content identity remains SHA-256 based within the run.  Provenance is
        intentionally scoped by run so identical generated bytes in two runs
        can retain their distinct immutable parents and creation commands.
        """

        self._run_dir(run_id)
        return ArtifactRegistry(self.root, Path("runs") / run_id / "registry")

    def _resource_authority_records(
        self, run_id: str
    ) -> tuple[dict[str, Any], ...]:
        """Read the monotonic validity authority outside the replaceable run tree."""
        return _read_resource_authority_records(self.root, run_id)

    def _persist_resource_authority(
        self,
        manifest: Mapping[str, Any],
        logical_type: str,
        state: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Advance the external monotonic resource head before run-local evidence."""

        return _persist_resource_authority_for(
            self.root, str(manifest["run_id"]), logical_type, state
        )

    def _resource_authority_descriptors(
        self, records: Sequence[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        """Canonical ledger commitments for the complete external history."""
        return _resource_authority_descriptors_for(records)

    def _validate_resource_authority_ledger(
        self,
        records: Sequence[Mapping[str, Any]],
        events: Sequence[Any],
    ) -> None:
        """Require every monotonic resource record at its exact ledger position."""

        _validate_resource_authority_ledger_for(records, events)

    def _manifest_path(self, run_id: str) -> Path:
        return self._run_dir(run_id) / "manifest.json"

    def load_manifest(self, run_id: str) -> dict[str, Any]:
        manifest = _read_json(self._manifest_path(run_id))
        if manifest.get("run_id") != run_id:
            raise OrchestrationError("run manifest identity mismatch")
        return manifest

    def _fixture_operation_receipt(
        self,
        run_id: str,
        *,
        required: bool = False,
    ) -> dict[str, Any] | None:
        """Read and strictly validate the bounded vNext operation receipt."""

        self._run_dir(run_id)
        relative = Path("runs") / run_id / "fixture-operation.json"
        try:
            raw = read_confined_bytes(
                self.root,
                relative,
                reject_hardlinks=True,
                max_bytes=1024 * 1024,
                missing_ok=True,
            )
        except (OSError, ValueError, PathSecurityError) as exc:
            raise OrchestrationError(
                "vNext fixture operation receipt is unsafe"
            ) from exc
        if raw is None:
            if required:
                raise OrchestrationError("vNext fixture operation receipt is absent")
            return None
        try:
            value = safe_json_loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise OrchestrationError(
                "vNext fixture operation receipt is malformed"
            ) from exc
        if not isinstance(value, dict):
            raise OrchestrationError(
                "vNext fixture operation receipt must be a JSON object"
            )

        schema_version = value.get("schema_version")
        if schema_version not in {
            VNEXT_LEGACY_OPERATION_SCHEMA_VERSION,
            VNEXT_OPERATION_SCHEMA_VERSION,
            VNEXT_RESTART_OPERATION_SCHEMA_VERSION,
        }:
            raise OrchestrationError(
                "vNext fixture operation receipt version is unsupported"
            )
        if (
            schema_version
            in {
                VNEXT_OPERATION_SCHEMA_VERSION,
                VNEXT_RESTART_OPERATION_SCHEMA_VERSION,
            }
            and raw != _canonical_bytes(value)
        ):
            raise OrchestrationError(
                "vNext fixture operation receipt is not canonical JSON"
            )
        base_fields = {
            "created_at",
            "error_type",
            "fixture_notice",
            "recovery_policy",
            "run_id",
            "schema_version",
            "status",
            "updated_at",
        }
        if schema_version in {
            VNEXT_OPERATION_SCHEMA_VERSION,
            VNEXT_RESTART_OPERATION_SCHEMA_VERSION,
        }:
            base_fields.update(
                {
                    "guarded_launch_receipt_sha256",
                    "launch_mode",
                }
            )
        if schema_version == VNEXT_RESTART_OPERATION_SCHEMA_VERSION:
            base_fields.update(
                {
                    "restart_from_run_id",
                    "restart_lineage_receipt_sha256",
                }
            )
        status = value.get("status")
        if status not in VNEXT_OPERATION_STATUS_POLICY:
            raise OrchestrationError(
                "vNext fixture operation receipt status is invalid"
            )
        expected_fields = set(base_fields)
        if status == "COMPLETE":
            expected_fields.update(
                {
                    "artifact_registry",
                    "event_ledger",
                    "summary_artifact_sha256",
                    "system_fixture_integrity",
                }
            )
        if set(value) != expected_fields:
            raise OrchestrationError(
                "vNext fixture operation receipt schema is invalid"
            )
        if (
            value.get("run_id") != run_id
            or value.get("fixture_notice") != VNEXT_FIXTURE_NOTICE
            or value.get("recovery_policy")
            != VNEXT_OPERATION_STATUS_POLICY[status]
        ):
            raise OrchestrationError(
                "vNext fixture operation receipt binding is invalid"
            )
        if schema_version in {
            VNEXT_OPERATION_SCHEMA_VERSION,
            VNEXT_RESTART_OPERATION_SCHEMA_VERSION,
        }:
            launch_mode = value.get("launch_mode")
            guarded_hash = value.get("guarded_launch_receipt_sha256")
            if launch_mode == VNEXT_DIRECT_LAUNCH_MODE:
                if guarded_hash is not None:
                    raise OrchestrationError(
                        "direct vNext fixture operation binds a guarded receipt"
                    )
            elif launch_mode == VNEXT_GUARDED_LAUNCH_MODE:
                if (
                    not isinstance(guarded_hash, str)
                    or re.fullmatch(r"[0-9a-f]{64}", guarded_hash) is None
                ):
                    raise OrchestrationError(
                        "guarded vNext fixture receipt hash is invalid"
                    )
            else:
                raise OrchestrationError(
                    "vNext fixture operation launch mode is invalid"
                )
        if schema_version == VNEXT_RESTART_OPERATION_SCHEMA_VERSION:
            restart_from_run_id = value.get("restart_from_run_id")
            restart_lineage_hash = value.get(
                "restart_lineage_receipt_sha256"
            )
            if (
                value.get("launch_mode") != VNEXT_GUARDED_LAUNCH_MODE
                or not isinstance(restart_from_run_id, str)
                or RUN_ID_PATTERN.fullmatch(restart_from_run_id) is None
                or restart_from_run_id == run_id
                or not isinstance(restart_lineage_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", restart_lineage_hash)
                is None
            ):
                raise OrchestrationError(
                    "vNext fixture restart lineage binding is invalid"
                )

        timestamps: list[datetime] = []
        for field in ("created_at", "updated_at"):
            timestamp = value.get(field)
            if (
                not isinstance(timestamp, str)
                or not timestamp.endswith("Z")
                or len(timestamp) > 64
            ):
                raise OrchestrationError(
                    "vNext fixture operation receipt timestamp is invalid"
                )
            try:
                parsed = datetime.fromisoformat(timestamp[:-1] + "+00:00")
            except ValueError as exc:
                raise OrchestrationError(
                    "vNext fixture operation receipt timestamp is invalid"
                ) from exc
            if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
                raise OrchestrationError(
                    "vNext fixture operation receipt timestamp is not UTC"
                )
            timestamps.append(parsed)
        if timestamps[1] < timestamps[0]:
            raise OrchestrationError(
                "vNext fixture operation receipt timestamps are non-monotonic"
            )

        error_type = value.get("error_type")
        if status == "FAILED":
            if (
                not isinstance(error_type, str)
                or not error_type
                or len(error_type) > 256
                or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]*", error_type) is None
            ):
                raise OrchestrationError(
                    "failed vNext fixture operation lacks a bounded error type"
                )
        elif error_type is not None:
            raise OrchestrationError(
                "non-failed vNext fixture operation records an error type"
            )

        if status == "COMPLETE":
            registry = value.get("artifact_registry")
            ledger = value.get("event_ledger")
            expected_registry_path = f"runs/{run_id}/registry"
            expected_ledger_path = f"runs/{run_id}/events.jsonl"
            if (
                not isinstance(registry, dict)
                or set(registry) != {"artifact_count", "base_path", "status"}
                or isinstance(registry.get("artifact_count"), bool)
                or not isinstance(registry.get("artifact_count"), int)
                or registry["artifact_count"] <= 0
                or registry.get("base_path") != expected_registry_path
                or registry.get("status") != "PASS"
            ):
                raise OrchestrationError(
                    "vNext fixture registry receipt is invalid"
                )
            if (
                not isinstance(ledger, dict)
                or set(ledger) != {"event_count", "head_hash", "path", "status"}
                or isinstance(ledger.get("event_count"), bool)
                or not isinstance(ledger.get("event_count"), int)
                or ledger["event_count"] <= 0
                or not isinstance(ledger.get("head_hash"), str)
                or re.fullmatch(r"[0-9a-f]{64}", ledger["head_hash"]) is None
                or ledger.get("path") != expected_ledger_path
                or ledger.get("status") != "PASS"
            ):
                raise OrchestrationError(
                    "vNext fixture ledger receipt is invalid"
                )
            summary_hash = value.get("summary_artifact_sha256")
            if (
                not isinstance(summary_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", summary_hash) is None
                or value.get("system_fixture_integrity") != "PASS"
            ):
                raise OrchestrationError(
                    "vNext fixture completion receipt is invalid"
                )
        if schema_version == VNEXT_LEGACY_OPERATION_SCHEMA_VERSION:
            value = dict(value)
            value["guarded_launch_receipt_sha256"] = None
            value["launch_mode"] = VNEXT_LEGACY_LAUNCH_MODE
        return value

    def _guarded_launch_receipt(
        self,
        run_id: str,
        operation: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """Validate the immutable operational receipt for a guarded launch."""

        mode = operation.get("launch_mode")
        relative = Path("runs") / run_id / "guarded-launch.json"
        try:
            raw = read_confined_bytes(
                self.root,
                relative,
                reject_hardlinks=True,
                max_bytes=4 * 1024 * 1024,
                missing_ok=True,
            )
        except (OSError, ValueError, PathSecurityError) as exc:
            raise OrchestrationError(
                "vNext guarded launch receipt is unsafe"
            ) from exc
        if mode == VNEXT_DIRECT_LAUNCH_MODE:
            if raw is not None:
                raise OrchestrationError(
                    "direct vNext fixture has ambiguous guarded launch data"
                )
            return None
        if mode == VNEXT_LEGACY_LAUNCH_MODE:
            return None
        if mode != VNEXT_GUARDED_LAUNCH_MODE or raw is None:
            raise OrchestrationError("vNext guarded launch receipt is absent")
        expected_hash = operation.get("guarded_launch_receipt_sha256")
        if not isinstance(expected_hash, str) or _sha256(raw) != expected_hash:
            raise OrchestrationError("vNext guarded launch receipt hash differs")
        try:
            value = safe_json_loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise OrchestrationError(
                "vNext guarded launch receipt is malformed"
            ) from exc
        expected_fields = {
            "canonical_project_root",
            "captured_source_inventory",
            "command_context",
            "created_at",
            "launch_mode",
            "root_identity",
            "run_id",
            "schema_version",
            "scientific_authority",
        }
        if (
            not isinstance(value, dict)
            or raw != _canonical_bytes(value)
            or set(value) != expected_fields
        ):
            raise OrchestrationError("vNext guarded launch receipt schema is invalid")
        root_identity = value.get("root_identity")
        if (
            value.get("schema_version") != VNEXT_GUARDED_LAUNCH_SCHEMA_VERSION
            or value.get("run_id") != run_id
            or value.get("launch_mode") != VNEXT_GUARDED_LAUNCH_MODE
            or value.get("created_at") != operation.get("created_at")
            or value.get("canonical_project_root") != str(self.root)
            or value.get("scientific_authority") is not False
            or not isinstance(root_identity, dict)
            or set(root_identity) != {"device", "inode"}
            or any(
                isinstance(root_identity.get(field), bool)
                or not isinstance(root_identity.get(field), int)
                or root_identity[field] < 0
                for field in ("device", "inode")
            )
            or (root_identity["device"], root_identity["inode"])
            != self._root_identity
            or _named_directory_identity(self.root) != self._root_identity
        ):
            raise OrchestrationError("vNext guarded launch receipt binding is invalid")
        command_context = value.get("command_context")
        if operation.get("schema_version") == VNEXT_RESTART_OPERATION_SCHEMA_VERSION:
            expected_commands = (
                _research_os_fixture_command_context(
                    run_id,
                    str(operation["restart_from_run_id"]),
                ),
            )
        else:
            expected_commands = (
                _research_os_fixture_command_context(None),
                _research_os_fixture_command_context(run_id),
            )
        if (
            not isinstance(command_context, list)
            or any(not isinstance(item, str) for item in command_context)
            or tuple(command_context) not in expected_commands
        ):
            raise OrchestrationError(
                "vNext guarded launch command binding is invalid"
            )
        inventory = value.get("captured_source_inventory")
        if (
            not isinstance(inventory, dict)
            or set(inventory)
            != {"aggregate_sha256", "entries", "kind", "schema_version"}
            or inventory.get("schema_version") != SCHEMA_VERSION
            or inventory.get("kind") != "FROZEN_SOURCE_INVENTORY"
            or not isinstance(inventory.get("entries"), list)
            or not inventory["entries"]
            or len(inventory["entries"]) > MAX_INVENTORY_ENTRIES
            or not isinstance(inventory.get("aggregate_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", inventory["aggregate_sha256"])
            is None
        ):
            raise OrchestrationError(
                "vNext guarded launch source inventory is invalid"
            )
        entries = inventory["entries"]
        paths: list[str] = []
        total_bytes = 0
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"path", "sha256", "size"}
                or not isinstance(entry.get("path"), str)
                or not entry["path"]
                or Path(entry["path"]).is_absolute()
                or any(
                    part in {"", ".", ".."}
                    for part in Path(entry["path"]).parts
                )
                or not isinstance(entry.get("sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
                or isinstance(entry.get("size"), bool)
                or not isinstance(entry.get("size"), int)
                or entry["size"] < 0
                or entry["size"] > 4 * 1024 * 1024
            ):
                raise OrchestrationError(
                    "vNext guarded launch source entry is invalid"
                )
            paths.append(entry["path"])
            total_bytes += entry["size"]
        if (
            total_bytes > MAX_INVENTORY_TOTAL_BYTES
            or paths != sorted(paths)
            or len(paths) != len(set(paths))
            or "scripts/scientist_one_cli.py" not in paths
            or any(
                path != "scripts/scientist_one_cli.py"
                and not (
                    path.startswith("src/scientist_one/")
                    and path.endswith(".py")
                )
                for path in paths
            )
            or _sha256(_canonical_bytes(entries))
            != inventory["aggregate_sha256"]
        ):
            raise OrchestrationError(
                "vNext guarded launch source inventory binding is invalid"
            )
        return value

    def _restart_lineage_receipt(
        self,
        run_id: str,
        operation: Mapping[str, Any],
        *,
        _visited_run_ids: frozenset[str] | None = None,
        _depth: int = 0,
    ) -> dict[str, Any] | None:
        """Revalidate a guarded new-run lineage against its abandoned source."""

        visited_run_ids = _visited_run_ids or frozenset()
        if run_id in visited_run_ids:
            raise OrchestrationError(
                "vNext restart lineage contains a cycle or duplicate run"
            )
        if _depth >= VNEXT_MAX_RESTART_LINEAGE_DEPTH:
            raise OrchestrationError(
                "vNext restart lineage exceeds its bounded maximum depth"
            )
        visited_run_ids = visited_run_ids | {run_id}

        relative = Path("runs") / run_id / "restart-lineage.json"
        try:
            raw = read_confined_bytes(
                self.root,
                relative,
                reject_hardlinks=True,
                max_bytes=1024 * 1024,
                missing_ok=True,
            )
        except (OSError, ValueError, PathSecurityError) as exc:
            raise OrchestrationError(
                "vNext restart lineage receipt is unsafe"
            ) from exc
        if operation.get("schema_version") != VNEXT_RESTART_OPERATION_SCHEMA_VERSION:
            if raw is not None:
                raise OrchestrationError(
                    "non-restart vNext fixture has ambiguous restart lineage"
                )
            return None
        if raw is None:
            raise OrchestrationError("vNext restart lineage receipt is absent")
        expected_hash = operation.get("restart_lineage_receipt_sha256")
        if not isinstance(expected_hash, str) or _sha256(raw) != expected_hash:
            raise OrchestrationError("vNext restart lineage receipt hash differs")
        try:
            value = safe_json_loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise OrchestrationError(
                "vNext restart lineage receipt is malformed"
            ) from exc
        expected_fields = {
            "abandoned_guarded_launch_receipt_sha256",
            "abandoned_launch_mode",
            "abandoned_operation_sha256",
            "abandoned_operation_schema_version",
            "abandoned_operation_status",
            "abandoned_resume_supported",
            "abandoned_run_id",
            "canonical_project_root",
            "created_at",
            "kind",
            "new_run_id",
            "protected_resources_reused",
            "recovery_semantics",
            "schema_version",
            "scientific_authority",
        }
        abandoned_run_id = operation.get("restart_from_run_id")
        if (
            not isinstance(value, dict)
            or raw != _canonical_bytes(value)
            or set(value) != expected_fields
            or value.get("schema_version")
            != VNEXT_RESTART_LINEAGE_SCHEMA_VERSION
            or value.get("kind") != "GUARDED_NEW_RUN_RESTART_LINEAGE"
            or value.get("new_run_id") != run_id
            or value.get("abandoned_run_id") != abandoned_run_id
            or value.get("abandoned_operation_status") != "IN_PROGRESS"
            or value.get("abandoned_launch_mode")
            != VNEXT_GUARDED_LAUNCH_MODE
            or value.get("abandoned_resume_supported") is not False
            or value.get("protected_resources_reused") is not False
            or value.get("recovery_semantics")
            != "NEW_RUN_NO_SAME_ID_RESUME"
            or value.get("scientific_authority") is not False
            or value.get("canonical_project_root") != str(self.root)
            or value.get("created_at") != operation.get("created_at")
            or not isinstance(abandoned_run_id, str)
            or abandoned_run_id == run_id
        ):
            raise OrchestrationError(
                "vNext restart lineage receipt binding is invalid"
            )
        for field in (
            "abandoned_guarded_launch_receipt_sha256",
            "abandoned_operation_sha256",
        ):
            digest = value.get(field)
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise OrchestrationError(
                    "vNext restart lineage source digest is invalid"
                )
        abandoned_operation = self._fixture_operation_receipt(
            abandoned_run_id,
            required=True,
        )
        abandoned_schema_version = (
            abandoned_operation.get("schema_version")
            if abandoned_operation is not None
            else None
        )
        if (
            abandoned_operation is None
            or abandoned_schema_version
            not in {
                VNEXT_OPERATION_SCHEMA_VERSION,
                VNEXT_RESTART_OPERATION_SCHEMA_VERSION,
            }
            or abandoned_schema_version
            != value.get("abandoned_operation_schema_version")
            or abandoned_operation.get("status") != "IN_PROGRESS"
            or abandoned_operation.get("launch_mode")
            != VNEXT_GUARDED_LAUNCH_MODE
            or abandoned_operation.get("recovery_policy")
            != VNEXT_OPERATION_STATUS_POLICY["IN_PROGRESS"]
            or abandoned_operation.get("guarded_launch_receipt_sha256")
            != value["abandoned_guarded_launch_receipt_sha256"]
        ):
            raise OrchestrationError(
                "vNext restart lineage source is no longer abandoned"
            )
        self._guarded_launch_receipt(
            abandoned_run_id,
            abandoned_operation,
        )
        if abandoned_schema_version == VNEXT_RESTART_OPERATION_SCHEMA_VERSION:
            self._restart_lineage_receipt(
                abandoned_run_id,
                abandoned_operation,
                _visited_run_ids=visited_run_ids,
                _depth=_depth + 1,
            )
        abandoned_raw = read_confined_bytes(
            self.root,
            Path("runs") / abandoned_run_id / "fixture-operation.json",
            reject_hardlinks=True,
            max_bytes=1024 * 1024,
        )
        if (
            abandoned_raw is None
            or _sha256(abandoned_raw) != value["abandoned_operation_sha256"]
        ):
            raise OrchestrationError(
                "vNext restart lineage source operation differs"
            )
        return value

    def _manifest_name_present(self, run_id: str) -> bool:
        """Detect even an unsafe manifest name so mixed authorities fail closed."""

        path = self._run_dir(run_id) / "manifest.json"
        return path.exists() or path.is_symlink()

    def _verify_vnext_autonomous_implementation(
        self,
        *,
        registry: ArtifactRegistry,
        registry_records: Mapping[str, Any],
        events: Sequence[Any],
        summary_record: Any,
        summary_value: Mapping[str, Any],
        research_objects: Sequence[Any],
        verification: dict[str, Any],
    ) -> None:
        """Rehydrate and independently verify the selected autonomous run.

        Registry and ledger closure prove that bytes were retained; they do not
        prove that a provider-selected implementation still names the reviewed
        worker, exact execution, recomputed result, or non-evidentiary canonical
        state.  This verifier deliberately starts from explicit summary roots and
        re-derives those semantic bindings rather than trusting persisted PASS
        labels.
        """

        from .autonomous_implementation import (
            ACTIONABLE_PROPOSAL_SCHEMA_VERSION,
            ACTION_SEMANTICS_SCHEMA_VERSION,
            ACTION_VALIDATION_SCHEMA_VERSION,
            DESCRIPTOR_SCHEMA_VERSION,
            LEGACY_DESCRIPTOR_SCHEMA_VERSION,
            LEGACY_WORKER_CONFIGURATION_SCHEMA_VERSION,
            PROVIDER_ADMISSION_LINK_SCHEMA_VERSION,
            PROVIDER_NEUTRALITY_SCHEMA_VERSION,
            ReviewedWorkerTemplate,
            WORKER_CONFIGURATION_SCHEMA_VERSION,
            template_review_payload,
        )
        from .experiments import (
            AdaptiveExecutionPlan,
            EvidenceClass,
            ExperimentPhase,
            FrozenRunSpec,
            OutputManifest,
            plan_adaptive_execution,
        )
        from .external import UNVERIFIED_TRANSPORT_AUTHORITY
        from .provider_verification import (
            ProviderVerificationError,
            require_provider_verifier,
        )

        result = verification

        def fail(message: str) -> None:
            raise OrchestrationError(
                f"vNext autonomous implementation verification failed: {message}"
            )

        def digest(value: object, label: str) -> str:
            if (
                not isinstance(value, str)
                or re.fullmatch(r"[0-9a-f]{64}", value) is None
            ):
                fail(f"{label} is not a SHA-256 digest")
            return value

        def record(
            value: object,
            label: str,
            *,
            logical_type: str,
            creator_role: Role,
            mime_type: str = "application/json",
        ) -> Any:
            key = digest(value, label)
            item = registry_records.get(key)
            if (
                item is None
                or item.logical_type != logical_type
                or item.creator_role is not creator_role
                or item.mime_type != mime_type
                or item.validation_result != "PASS"
                or item.frozen is not True
                or registry.verify(key) is not True
            ):
                fail(f"{label} has invalid registry authority")
            return item

        def json_value(
            item: Any,
            label: str,
            *,
            canonical_newline: bool | None = True,
        ) -> Mapping[str, Any]:
            raw = registry.get_bytes(item.sha256)
            value = safe_json_loads(raw)
            if not isinstance(value, Mapping):
                fail(f"{label} is not a JSON object")
            canonical = canonical_json_bytes(dict(value))
            if canonical_newline is True and raw != canonical + b"\n":
                fail(f"{label} is not canonical newline-terminated JSON")
            if canonical_newline is False and raw != canonical:
                fail(f"{label} is not canonical JSON")
            return value

        def exact_keys(
            value: Mapping[str, Any], expected: set[str], label: str
        ) -> None:
            if set(value) != expected:
                fail(f"{label} has missing or unknown fields")

        def text_descriptor(value: str) -> dict[str, object]:
            encoded = value.encode("utf-8")
            return {
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "size": len(encoded),
                "value_persisted": False,
            }

        autonomous = summary_value.get("autonomous_implementation")
        if not isinstance(autonomous, Mapping):
            fail("summary lacks autonomous implementation state")
        provider_neutral_v2, artifacts, object_ids = (
            _replay_vnext_autonomous_summary_roots(
                autonomous,
                provider_neutrality_schema=PROVIDER_NEUTRALITY_SCHEMA_VERSION,
                registry_records=registry_records,
            )
        )
        neutrality_schema = autonomous.get("provider_neutrality_schema")
        if (
            autonomous.get("admission_status") != "ADMITTED"
            or autonomous.get("execution_state") != "SUCCEEDED"
            or autonomous.get("provider_status") != "COMPLETED"
            or autonomous.get("network_used") is not False
            or autonomous.get("network_use_status") != "UNKNOWN_UNATTESTED"
            or autonomous.get("network_isolation_attested") is not False
            or autonomous.get("scientific_evidence") is not False
            or autonomous.get("semantic_validation_status") != "PASS"
        ):
            fail("summary promotes or misclassifies the autonomous execution")
        try:
            selected_template = ReviewedWorkerTemplate(
                autonomous.get("template_id")
            )
        except (TypeError, ValueError) as exc:
            raise OrchestrationError(
                "vNext autonomous implementation verification failed: "
                "summary names an unknown template"
            ) from exc
        result["summary_binding_valid"] = True
        result["network_use_status"] = "UNKNOWN_UNATTESTED"
        result["provider_neutral"] = provider_neutral_v2
        result["provider_neutrality_schema"] = (
            neutrality_schema if provider_neutral_v2 else None
        )
        result["historical_v1_replay"] = not provider_neutral_v2
        result["current_production_eligible"] = provider_neutral_v2

        catalog_record = record(
            artifacts["catalog"],
            "template catalog",
            logical_type="autonomous_implementation.template_catalog",
            creator_role=Role.ORCHESTRATOR,
        )
        derivation_record = record(
            artifacts["data_derivation"],
            "data derivation",
            logical_type="autonomous_implementation.fixture_data_derivation",
            creator_role=Role.EVIDENCE_CURATOR,
        )
        data_record = record(
            artifacts["data"],
            "autonomous data",
            logical_type="autonomous_implementation.fixture_data",
            creator_role=Role.EVIDENCE_CURATOR,
        )
        evaluator_record = record(
            artifacts["evaluator"],
            "autonomous evaluator",
            logical_type="autonomous_implementation.fixture_evaluator",
            creator_role=Role.PROTOCOL_DESIGNER,
        )
        proposal_record = record(
            artifacts["proposal"],
            "actionable proposal" if provider_neutral_v2 else "provider proposal",
            logical_type=(
                "autonomous_implementation.actionable_proposal"
                if provider_neutral_v2
                else "autonomous_implementation.model_proposal"
            ),
            creator_role=Role.ORCHESTRATOR,
        )
        provider_attempt_record = (
            record(
                artifacts["provider_attempt"],
                "provider proposal attempt",
                logical_type="autonomous_implementation.model_proposal",
                creator_role=Role.ORCHESTRATOR,
            )
            if provider_neutral_v2
            else proposal_record
        )
        provider_link_record = (
            record(
                artifacts["provider_admission_link"],
                "provider admission link",
                logical_type="autonomous_implementation.provider_admission_link",
                creator_role=Role.ORCHESTRATOR,
            )
            if provider_neutral_v2
            else None
        )
        validation_record = record(
            artifacts["validation_receipt"],
            "admission receipt",
            logical_type="autonomous_implementation.validation_receipt",
            creator_role=Role.ORCHESTRATOR,
        )
        worker_record = record(
            artifacts["worker_code"],
            "reviewed worker",
            logical_type="autonomous_implementation.reviewed_worker_code",
            creator_role=Role.IMPLEMENTER,
            mime_type="text/x-python",
        )
        configuration_record = record(
            artifacts["configuration"],
            "worker configuration",
            logical_type="autonomous_implementation.worker_configuration",
            creator_role=Role.IMPLEMENTER,
        )
        descriptor_record = record(
            artifacts["descriptor"],
            "admitted descriptor",
            logical_type="autonomous_implementation.admitted_descriptor",
            creator_role=Role.IMPLEMENTER,
        )
        spec_record = record(
            artifacts["frozen_spec"],
            "frozen run spec",
            logical_type="autonomous_implementation.frozen_run_spec",
            creator_role=Role.EXPERIMENT_RUNNER,
        )
        plan_record = record(
            artifacts["execution_plan"],
            "adaptive execution plan",
            logical_type="adaptive_execution_plan",
            creator_role=Role.EXPERIMENT_RUNNER,
        )
        input_binding_record = (
            record(
                artifacts["execution_input_binding"],
                "execution input binding",
                logical_type="execution_input_binding",
                creator_role=Role.EXPERIMENT_RUNNER,
            )
            if provider_neutral_v2
            else None
        )
        plan_binding_record = record(
            artifacts["execution_plan_binding"],
            "adaptive execution plan binding",
            logical_type="adaptive_execution_plan_binding",
            creator_role=Role.EXPERIMENT_RUNNER,
        )
        manifest_record = record(
            artifacts["manifest"],
            "output manifest",
            logical_type="experiment_output_manifest",
            creator_role=Role.EXPERIMENT_RUNNER,
        )
        execution_receipt_record = record(
            artifacts["execution_receipt"],
            "execution receipt",
            logical_type="autonomous_implementation.execution_receipt",
            creator_role=Role.EXPERIMENT_RUNNER,
        )
        semantic_record = record(
            artifacts["semantic_validation"],
            "semantic validation",
            logical_type="autonomous_implementation.semantic_validation",
            creator_role=Role.SCIENTIFIC_REVIEWER,
        )
        expected_component_schemas = (
            (provider_attempt_record, "1.0"),
            (proposal_record, "1.0"),
            (worker_record, "1.0"),
            (
                configuration_record,
                "2.0" if provider_neutral_v2 else "1.0",
            ),
            (validation_record, "2.0" if provider_neutral_v2 else "1.0"),
            (descriptor_record, "2.0" if provider_neutral_v2 else "1.0"),
        )
        if provider_link_record is not None:
            expected_component_schemas = (
                *expected_component_schemas,
                (provider_link_record, "1.0"),
            )
        if any(
            item.schema_version != expected_schema
            for item, expected_schema in expected_component_schemas
        ):
            fail("autonomous component artifact schema history is inconsistent")

        derivation = json_value(derivation_record, "data derivation")
        exact_keys(
            derivation,
            {
                "fixture_notice",
                "schema_version",
                "scientific_evidence",
                "selected_row_ids",
                "selection",
                "source_dataset_sha256",
                "values",
            },
            "data derivation",
        )
        source_dataset_sha256 = digest(
            derivation.get("source_dataset_sha256"), "source dataset"
        )
        source_dataset_record = record(
            source_dataset_sha256,
            "source dataset",
            logical_type="dataset_fixture",
            creator_role=Role.EVIDENCE_CURATOR,
        )
        if (
            derivation.get("schema_version")
            != "AUTONOMOUS_IMPLEMENTATION_FIXTURE_DATA_DERIVATION_V1"
            or derivation.get("fixture_notice") != VNEXT_FIXTURE_NOTICE
            or derivation.get("scientific_evidence") is not False
            or derivation.get("selection")
            != {
                "field": "signal",
                "limit": 4,
                "ordering": "dataset_row_order",
                "split": "development",
            }
            or set(derivation_record.parent_artifacts)
            != {source_dataset_sha256}
        ):
            fail("data derivation policy or provenance changed")
        source_dataset = json_value(
            source_dataset_record,
            "source dataset",
            canonical_newline=None,
        )
        rows = source_dataset.get("rows")
        if not isinstance(rows, list):
            fail("source dataset rows are absent")
        selected_rows = [
            row
            for row in rows
            if isinstance(row, Mapping) and row.get("split") == "development"
        ][:4]
        selected_ids = [row.get("id") for row in selected_rows]
        selected_values = [row.get("signal") for row in selected_rows]
        if (
            len(selected_rows) != 4
            or any(
                not isinstance(identifier, str) or not identifier
                for identifier in selected_ids
            )
            or any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                for value in selected_values
            )
            or derivation.get("selected_row_ids") != selected_ids
            or derivation.get("values") != selected_values
        ):
            fail("derived data does not match the frozen source selection")
        data = json_value(data_record, "autonomous data")
        if (
            data != {"values": selected_values}
            or set(data_record.parent_artifacts) != {derivation_record.sha256}
        ):
            fail("autonomous data does not bind the derivation receipt")
        evaluator = json_value(evaluator_record, "autonomous evaluator")
        if evaluator != {
            "direction": "HIGHER_IS_BETTER",
            "metric": "template_defined_scalar",
            "metric_id": "metric-autonomous-template-scalar",
        }:
            fail("autonomous evaluator changed")
        if len(evaluator_record.parent_artifacts) != 1:
            fail("autonomous evaluator has ambiguous provenance")
        record(
            evaluator_record.parent_artifacts[0],
            "foundation evaluator",
            logical_type="metric_evaluator",
            creator_role=Role.PROTOCOL_DESIGNER,
        )

        catalog = json_value(catalog_record, "template catalog")
        exact_keys(
            catalog,
            {
                "catalog_id",
                "catalog_version",
                "execution_authority",
                "generation_policy",
                "provider_output_trust",
                "schema_version",
                "templates",
            },
            "template catalog",
        )
        templates = catalog.get("templates")
        if (
            catalog.get("schema_version")
            != "AUTONOMOUS_IMPLEMENTATION_CATALOG_V1"
            or catalog.get("catalog_id") != "bounded-experiment-workers"
            or catalog.get("catalog_version") != "1.0"
            or catalog.get("generation_policy")
            != "closed_deterministic_catalog_only"
            or catalog.get("provider_output_trust")
            != "UNTRUSTED_NON_EVIDENTIARY"
            or catalog.get("execution_authority")
            != "ADMITTED_FROZEN_RUN_SPEC_LOCAL_MAC_ONLY"
            or not isinstance(templates, list)
            or len(templates) != len(ReviewedWorkerTemplate)
        ):
            fail("template catalog payload is invalid")
        limits = {
            ReviewedWorkerTemplate.AFFINE_MEAN_V1: {
                "bias": {"minimum": -10.0, "maximum": 10.0},
                "scale": {"minimum": 0.1, "maximum": 10.0},
            },
            ReviewedWorkerTemplate.THRESHOLD_RATE_V1: {
                "positive_weight": {"minimum": 0.1, "maximum": 10.0},
                "threshold": {"minimum": -100.0, "maximum": 100.0},
            },
        }
        legacy_worker_sha256s = {
            ReviewedWorkerTemplate.AFFINE_MEAN_V1: (
                "ebace474b801092b10756ea833629648783e5e30d2c72eaa92d374637d73b370"
            ),
            ReviewedWorkerTemplate.THRESHOLD_RATE_V1: (
                "be8adbc6591869c28620359cd584deb5d0034431efc0597b00a566bfbfa65953"
            ),
        }
        catalog_by_template: dict[ReviewedWorkerTemplate, Mapping[str, Any]] = {}
        review_records: dict[ReviewedWorkerTemplate, Any] = {}
        for template_value in templates:
            if not isinstance(template_value, Mapping):
                fail("catalog template is malformed")
            exact_keys(
                template_value,
                {
                    "network_allowed",
                    "parameter_limits",
                    "review_artifact_sha256",
                    "shell_allowed",
                    "template_id",
                    "template_version",
                    "worker_code_sha256",
                },
                "catalog template",
            )
            try:
                template_id = ReviewedWorkerTemplate(template_value.get("template_id"))
            except (TypeError, ValueError) as exc:
                raise OrchestrationError(
                    "vNext autonomous implementation verification failed: "
                    "catalog contains an unknown template"
                ) from exc
            if template_id in catalog_by_template:
                fail("catalog repeats a template")
            review_record = record(
                template_value.get("review_artifact_sha256"),
                f"review for {template_id.value}",
                logical_type="autonomous_implementation.template_review",
                creator_role=(
                    Role.SCIENTIFIC_REVIEWER
                    if template_id is ReviewedWorkerTemplate.AFFINE_MEAN_V1
                    else Role.ADVERSARIAL_REVIEWER
                ),
            )
            review = json_value(review_record, f"review for {template_id.value}")
            expected_review = (
                template_review_payload(template_id)
                if provider_neutral_v2
                else {
                    "schema_version": (
                        "AUTONOMOUS_IMPLEMENTATION_TEMPLATE_REVIEW_V1"
                    ),
                    "template_id": template_id.value,
                    "template_version": "1.0",
                    "worker_code_sha256": legacy_worker_sha256s[template_id],
                    "review_scope": (
                        "deterministic_fixture_worker_no_shell_no_network"
                    ),
                    "shell_allowed": False,
                    "network_allowed": False,
                    "verdict": "APPROVED",
                }
            )
            if (
                review != expected_review
                or template_value.get("template_version") != "1.0"
                or template_value.get("worker_code_sha256")
                != expected_review["worker_code_sha256"]
                or template_value.get("parameter_limits") != limits[template_id]
                or template_value.get("shell_allowed") is not False
                or template_value.get("network_allowed") is not False
            ):
                fail("catalog template differs from its pinned review")
            catalog_by_template[template_id] = template_value
            review_records[template_id] = review_record
        if set(catalog_by_template) != set(ReviewedWorkerTemplate) or set(
            catalog_record.parent_artifacts
        ) != {item.sha256 for item in review_records.values()}:
            fail("catalog does not bind the complete pinned review set")

        proposal_attempt = json_value(
            provider_attempt_record,
            "provider proposal attempt",
        )
        exact_keys(
            proposal_attempt,
            {
                "capability",
                "declared_input_artifact_hashes",
                "invocation_id",
                "model_requested",
                "output",
                "provider_id",
                "provider_tools",
                "result_status",
                "schema_version",
                "scientific_evidence",
                "trust_class",
            },
            "provider proposal",
        )
        provider_proposal = proposal_attempt.get("output")
        if not isinstance(provider_proposal, Mapping):
            fail("provider proposal output is not structured")
        exact_keys(
            provider_proposal,
            {
                "implementation_id",
                "parameters",
                "parent_evidence_sha256s",
                "proposal_id",
                "rationale",
                "schema_version",
                "template_id",
            },
            "implementation proposal",
        )
        if (
            proposal_attempt.get("schema_version")
            != "AUTONOMOUS_IMPLEMENTATION_PROVIDER_ATTEMPT_V1"
            or proposal_attempt.get("capability") != "coding"
            or proposal_attempt.get("result_status") != "COMPLETED"
            or proposal_attempt.get("trust_class") != "UNTRUSTED_ADVISORY"
            or proposal_attempt.get("scientific_evidence") is not False
            or proposal_attempt.get("provider_tools") is not False
            or provider_proposal.get("schema_version")
            != "AUTONOMOUS_IMPLEMENTATION_PROPOSAL_V1"
            or provider_proposal.get("template_id") != selected_template.value
            or provider_proposal.get("parent_evidence_sha256s")
            != [data_record.sha256, evaluator_record.sha256]
            or proposal_attempt.get("declared_input_artifact_hashes")
            != [data_record.sha256, evaluator_record.sha256]
        ):
            fail("provider proposal authority or evidence binding is invalid")
        provider_implementation_id = provider_proposal.get("implementation_id")
        provider_proposal_id = provider_proposal.get("proposal_id")
        if not isinstance(provider_implementation_id, str) or not isinstance(
            provider_proposal_id,
            str,
        ):
            fail("provider proposal identities are invalid")
        parameters = provider_proposal.get("parameters")
        if not isinstance(parameters, list) or len(parameters) != 2:
            fail("proposal parameters are malformed")
        parameter_map: dict[str, float] = {}
        for item in parameters:
            if not isinstance(item, Mapping) or set(item) != {"name", "value"}:
                fail("proposal parameter entry is malformed")
            name = item.get("name")
            value = item.get("value")
            if (
                not isinstance(name, str)
                or name in parameter_map
                or isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
            ):
                fail("proposal parameter is invalid")
            parameter_map[name] = float(value)
        expected_limits = limits[selected_template]
        if set(parameter_map) != set(expected_limits) or any(
            not expected_limits[name]["minimum"]
            <= value
            <= expected_limits[name]["maximum"]
            for name, value in parameter_map.items()
        ):
            fail("proposal parameters exceed the reviewed template")

        neutral_evidence_hashes = tuple(
            sorted((data_record.sha256, evaluator_record.sha256))
        )
        action_semantics = {
            "schema_version": ACTION_SEMANTICS_SCHEMA_VERSION,
            "experiment_id": object_ids.get("Experiment"),
            "hypothesis_id": "hypothesis-threshold",
            "phase": "EXPLORATORY",
            "template_id": selected_template.value,
            "template_version": "1.0",
            "parameters": dict(sorted(parameter_map.items())),
            "parent_evidence_sha256s": list(neutral_evidence_hashes),
            "data_sha256": data_record.sha256,
            "evaluator_sha256": evaluator_record.sha256,
            "seeds": [3, 7],
        }
        semantic_id = hashlib.sha256(
            canonical_json_bytes(action_semantics)
        ).hexdigest()
        normalized_proposal = {
            "schema_version": "AUTONOMOUS_IMPLEMENTATION_PROPOSAL_V1",
            "proposal_id": f"action-{semantic_id}",
            "implementation_id": f"implementation-{semantic_id}",
            "template_id": selected_template.value,
            "parameters": [
                {"name": name, "value": value}
                for name, value in sorted(parameter_map.items())
            ],
            "parent_evidence_sha256s": list(neutral_evidence_hashes),
            "rationale": (
                "Source-owned deterministic normalization of an admitted "
                "reviewed-template action."
            ),
        }
        if provider_neutral_v2:
            actionable_proposal = json_value(
                proposal_record,
                "actionable proposal",
            )
            expected_actionable_proposal = {
                "schema_version": ACTIONABLE_PROPOSAL_SCHEMA_VERSION,
                "semantic_id": semantic_id,
                "semantics": action_semantics,
                "proposal": normalized_proposal,
                "catalog_artifact_sha256": catalog_record.sha256,
                "provider_identity_included": False,
                "scientific_evidence": False,
            }
            if (
                actionable_proposal != expected_actionable_proposal
                or proposal_record.parent_artifacts
                != (catalog_record.sha256, *neutral_evidence_hashes)
            ):
                fail("provider-neutral actionable proposal is inconsistent")
            implementation_id = normalized_proposal["implementation_id"]
            proposal_id = normalized_proposal["proposal_id"]
        else:
            implementation_id = provider_implementation_id
            proposal_id = provider_proposal_id
        if object_ids.get("Implementation") != implementation_id:
            fail("proposal identities differ from canonical summary roots")

        evidence_hashes = (data_record.sha256, evaluator_record.sha256)
        expected_provider_types = (
            "model_judged_instructions",
            "model_judged_input",
            "model_output_schema",
            "model_invocation",
            "model_provider_request_body",
            "model_provider_request_intent",
            "external_request",
            "external_response_raw",
            "external_response_receipt",
            "model_provider_response",
            "model_output",
        )
        if (
            tuple(provider_attempt_record.parent_artifacts[: len(evidence_hashes)])
            != evidence_hashes
            or len(provider_attempt_record.parent_artifacts)
            != len(evidence_hashes) + len(expected_provider_types)
        ):
            fail("proposal omits or reorders captured provider provenance")
        provider_parents: list[Any] = []
        for index, logical_type in enumerate(expected_provider_types):
            parent_hash = provider_attempt_record.parent_artifacts[
                len(evidence_hashes) + index
            ]
            provider_parents.append(
                record(
                    parent_hash,
                    f"captured provider record {logical_type}",
                    logical_type=logical_type,
                    creator_role=(
                        Role.EVIDENCE_CURATOR
                        if logical_type
                        in {"external_response_raw", "external_response_receipt"}
                        else Role.ORCHESTRATOR
                    ),
                    mime_type=(
                        "text/plain"
                        if logical_type
                        in {"model_judged_instructions", "model_judged_input"}
                        else "application/octet-stream"
                        if logical_type == "external_response_raw"
                        else "application/json"
                    ),
                )
            )
        if (
            tuple(item.logical_type for item in provider_parents)
            != expected_provider_types
            or any(
                item.schema_version
                != {
                    "external_request": (
                        EGRESS_REQUEST_SCHEMA if provider_neutral_v2 else "1.0"
                    ),
                    "external_response_receipt": (
                        EGRESS_RESPONSE_RECEIPT_SCHEMA
                        if provider_neutral_v2
                        else "1.0"
                    ),
                }.get(item.logical_type, "1.0")
                for item in provider_parents
            )
        ):
            fail("captured provider graph has an invalid schema or order")
        (
            instructions_record,
            input_record,
            schema_record,
            invocation_record,
            request_body_record,
            request_intent_record,
            external_request_record,
            raw_response_record,
            response_receipt_record,
            provider_response_record,
            output_record,
        ) = provider_parents
        invocation = json_value(invocation_record, "model invocation")
        model_output = json_value(output_record, "model output")
        exact_keys(
            invocation,
            {
                "capability",
                "input_artifact_hashes",
                "input_text",
                "instructions",
                "invocation_id",
                "kind",
                "max_output_tokens",
                "model",
                "output_schema",
                "prompt_template",
                "provider_id",
                "provider_tools",
                "schema_version",
                "scientific_evidence",
                "secret_values_persisted",
            },
            "model invocation",
        )
        all_parameter_names = sorted(
            {
                name
                for template_limits in limits.values()
                for name in template_limits
            }
        )
        proposal_schema = {
            "type": "object",
            "properties": {
                "schema_version": {
                    "type": "string",
                    "enum": ["AUTONOMOUS_IMPLEMENTATION_PROPOSAL_V1"],
                },
                "proposal_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                },
                "implementation_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                },
                "template_id": {
                    "type": "string",
                    "enum": [item.value for item in ReviewedWorkerTemplate],
                },
                "parameters": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "enum": all_parameter_names},
                            "value": {
                                "type": "number",
                                "minimum": -100.0,
                                "maximum": 100.0,
                            },
                        },
                        "required": ["name", "value"],
                        "additionalProperties": False,
                    },
                    "minItems": 2,
                    "maxItems": 2,
                },
                "parent_evidence_sha256s": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 64, "maxLength": 64},
                    "minItems": 1,
                    "maxItems": 32,
                },
                "rationale": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 2048,
                },
            },
            "required": [
                "schema_version",
                "proposal_id",
                "implementation_id",
                "template_id",
                "parameters",
                "parent_evidence_sha256s",
                "rationale",
            ],
            "additionalProperties": False,
        }
        invocation_id = proposal_attempt.get("invocation_id")
        model_requested = proposal_attempt.get("model_requested")
        provider_id = proposal_attempt.get("provider_id")
        expected_invocation_id = "research-os-fixture-autonomous-implementation"
        expected_model = "gpt-5"
        try:
            provider_contract = require_provider_verifier(
                provider_id,
                invocation_record.schema_version,
            )
        except ProviderVerificationError as exc:
            raise OrchestrationError(
                "vNext autonomous implementation verification failed: "
                "provider custody has no source-owned verifier"
            ) from exc
        expected_provider_id = provider_contract.provider_id
        expected_instructions = (
            "Select only a reviewed declarative template. Return strict JSON; "
            "never provide source, commands, paths, dependencies, or network policy."
        )
        expected_input_text = (
            "Propose one bounded non-evidentiary implementation for the supplied "
            "synthetic data and evaluator artifacts."
        )
        if (
            invocation_id != expected_invocation_id
            or model_requested != expected_model
            or provider_id != expected_provider_id
            or invocation.get("schema_version") != "1.0"
            or invocation.get("kind") != "MODEL_INVOCATION"
            or invocation.get("invocation_id") != text_descriptor(invocation_id)
            or invocation.get("provider_id") != provider_id
            or invocation.get("capability") != "coding"
            or invocation.get("model") != text_descriptor(model_requested)
            or invocation.get("prompt_template")
            != {
                "id": text_descriptor("bounded-implementation-proposal"),
                "version": text_descriptor("1.0"),
                "sha256": hashlib.sha256(
                    b"bounded-implementation-proposal-v1"
                ).hexdigest(),
            }
            or invocation.get("instructions")
            != text_descriptor(expected_instructions)
            or invocation.get("input_text") != text_descriptor(expected_input_text)
            or invocation.get("input_artifact_hashes")
            != [data_record.sha256, evaluator_record.sha256]
            or invocation.get("output_schema")
            != {
                "sha256": hashlib.sha256(
                    canonical_json_bytes(proposal_schema)
                ).hexdigest(),
                "value_persisted": False,
            }
            or invocation.get("max_output_tokens") != 1024
            or invocation.get("provider_tools") is not False
            or invocation.get("scientific_evidence") is not False
            or invocation.get("secret_values_persisted") is not False
            or invocation_record.parent_artifacts != evidence_hashes
        ):
            fail("captured model invocation is inconsistent")
        instructions_bytes = registry.get_bytes(instructions_record.sha256)
        input_bytes = registry.get_bytes(input_record.sha256)
        schema_bytes = registry.get_bytes(schema_record.sha256)
        request_body_bytes = registry.get_bytes(request_body_record.sha256)
        expected_schema_bytes = canonical_json_bytes(proposal_schema)
        try:
            request_projection = provider_contract.validate_and_project_request(
                body_bytes=request_body_bytes,
                retained_instructions=expected_instructions,
                retained_input=expected_input_text,
                retained_schema=proposal_schema,
                invocation_id=expected_invocation_id,
                model_requested=expected_model,
                maximum_output_tokens=1024,
            )
        except ProviderVerificationError as exc:
            raise OrchestrationError(
                "vNext autonomous implementation verification failed: "
                "provider request violates its source-owned wire contract"
            ) from exc
        if (
            instructions_bytes != expected_instructions.encode("utf-8")
            or input_bytes != expected_input_text.encode("utf-8")
            or schema_bytes != expected_schema_bytes
            or any(
                item.parent_artifacts
                for item in (
                    instructions_record,
                    input_record,
                    schema_record,
                    request_body_record,
                    raw_response_record,
                )
            )
        ):
            fail("captured provider inputs or leaf ancestry are inconsistent")

        body_sha256 = request_projection.body_sha256
        request_id = request_projection.request_id
        request_intent = json_value(
            request_intent_record, "provider request intent"
        )
        if (
            request_intent
            != {
                "schema_version": "1.0",
                "kind": "MODEL_PROVIDER_REQUEST_INTENT",
                "invocation_artifact_sha256": invocation_record.sha256,
                "request_body_artifact_sha256": request_body_record.sha256,
                "request_id": request_id,
                "provider_id": expected_provider_id,
                "method": "POST",
                "endpoint": provider_contract.endpoint,
                "body_sha256": body_sha256,
                "body_size": request_projection.body_size,
                "credential_value_persisted": False,
                "scientific_evidence": False,
            }
            or request_intent_record.parent_artifacts
            != (invocation_record.sha256, request_body_record.sha256)
        ):
            fail("captured provider request intent is inconsistent")

        external_request = json_value(
            external_request_record, "external provider request"
        )
        policy_claim_sha256 = external_request.get("policy_claim_sha256")
        budget_policy = {
            "schema_version": EGRESS_BUDGET_SCHEMA,
            "maximum_total_bytes": 32 * 1024 * 1024,
            "byte_accounting": (
                "REQUEST_BODY_PER_ATTEMPT_PLUS_EACH_RECEIVED_RESPONSE_BODY"
            ),
            "deadline_budget_seconds": 60.0,
            "deadline_scope": (
                "MONOTONIC_EXECUTE_ENTRY_THROUGH_FINAL_RESPONSE_CAPTURE"
            ),
        }
        expected_external_request = {
            "schema_version": (
                EGRESS_REQUEST_SCHEMA if provider_neutral_v2 else "1.0"
            ),
            "kind": "REDACTED_EXTERNAL_REQUEST",
            "request_id": request_id,
            "policy_id": provider_contract.provider_version,
            "adapter_id": expected_provider_id,
            "method": "POST",
            "url": provider_contract.endpoint,
            "headers": [
                ["Accept", "application/json"],
                ["User-Agent", "Scientist-One-vNext/1"],
                ["Idempotency-Key", expected_invocation_id],
            ],
            "body_sha256": body_sha256,
            "body_size": request_projection.body_size,
            "content_type": "application/json",
            "credential_env_name": provider_contract.credential_env_name,
            "credential_present": provider_contract.credential_present,
            "parent_artifacts": [request_intent_record.sha256],
            "scientific_evidence": False,
        }
        if provider_neutral_v2:
            expected_external_request.update(
                {
                    "policy_claim_sha256": policy_claim_sha256,
                    "egress_budget": budget_policy,
                }
            )
        if (
            external_request != expected_external_request
            or (
                provider_neutral_v2
                and (
                    not isinstance(policy_claim_sha256, str)
                    or len(policy_claim_sha256) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in policy_claim_sha256
                    )
                )
            )
            or external_request_record.parent_artifacts
            != (request_intent_record.sha256,)
        ):
            fail("captured external request is inconsistent")

        expected_usage = {
            "input_tokens": 40,
            "output_tokens": 48,
            "total_tokens": 88,
        }
        raw_response_bytes = registry.get_bytes(raw_response_record.sha256)
        try:
            response_projection = provider_contract.parse_and_project_response(
                raw_bytes=raw_response_bytes,
                requested_model=expected_model,
                output_schema=proposal_schema,
                maximum_output_bytes=32 * 1024 * 1024,
                expected_request_id=request_id,
            )
        except ProviderVerificationError as exc:
            raise OrchestrationError(
                "vNext autonomous implementation verification failed: "
                "provider response violates its source-owned wire contract"
            ) from exc
        expected_response_id = response_projection.response_id
        if (
            response_projection.model_returned != expected_model
            or thaw_json(response_projection.output) != dict(provider_proposal)
            or thaw_json(response_projection.usage) != expected_usage
            or model_output.get("provider_response_id") != expected_response_id
        ):
            fail("captured provider response projection is inconsistent")
        raw_response_sha256 = hashlib.sha256(raw_response_bytes).hexdigest()
        receipt = json_value(response_receipt_record, "provider response receipt")
        receipt_fields = {
            "attempts",
            "body_size",
            "captured_at",
            "content_type",
            "external_validation",
            "headers",
            "kind",
            "network_used",
            "raw_response_record_sha256",
            "raw_response_sha256",
            "request_artifact_sha256",
            "request_id",
            "schema_version",
            "scientific_evidence",
            "status_code",
            "transport_authority",
        }
        if provider_neutral_v2:
            receipt_fields.update({"policy_claim_sha256", "egress_budget"})
        exact_keys(receipt, receipt_fields, "provider response receipt")
        expected_attempt = {
            "attempt": 1,
            "status": "RESPONSE",
            "status_code": 200,
            "body_sha256": raw_response_sha256,
            "body_size": len(raw_response_bytes),
            "raw_response_record_sha256": raw_response_record.sha256,
        }
        if provider_neutral_v2:
            expected_attempt.update(
                {
                    "schema_version": EGRESS_ATTEMPT_SCHEMA,
                    "request_body_bytes": len(request_body_bytes),
                    "response_body_bytes": len(raw_response_bytes),
                    "cumulative_bytes": (
                        len(request_body_bytes) + len(raw_response_bytes)
                    ),
                    "retry_delay_seconds": None,
                }
            )
        captured_at = receipt.get("captured_at")
        attempt = receipt.get("attempts")
        attempt_offsets_valid = (
            isinstance(attempt, list)
            and len(attempt) == 1
            and isinstance(attempt[0], Mapping)
            and isinstance(attempt[0].get("started_offset_seconds"), (int, float))
            and not isinstance(attempt[0].get("started_offset_seconds"), bool)
            and isinstance(attempt[0].get("completed_offset_seconds"), (int, float))
            and not isinstance(attempt[0].get("completed_offset_seconds"), bool)
            and float(attempt[0]["completed_offset_seconds"])
            >= float(attempt[0]["started_offset_seconds"])
        )
        if (
            receipt.get("schema_version")
            != (EGRESS_RESPONSE_RECEIPT_SCHEMA if provider_neutral_v2 else "1.0")
            or receipt.get("kind") != "EXTERNAL_RESPONSE_RECEIPT"
            or receipt.get("request_id") != request_id
            or (
                provider_neutral_v2
                and receipt.get("policy_claim_sha256") != policy_claim_sha256
            )
            or receipt.get("request_artifact_sha256")
            != external_request_record.sha256
            or receipt.get("raw_response_sha256") != raw_response_sha256
            or receipt.get("raw_response_record_sha256")
            != raw_response_record.sha256
            or receipt.get("status_code") != 200
            or receipt.get("content_type") != "application/json"
            or receipt.get("body_size") != len(raw_response_bytes)
            or receipt.get("headers") != {"content-type": "application/json"}
            or (
                provider_neutral_v2
                and (
                    not attempt_offsets_valid
                    or {
                        key: value
                        for key, value in attempt[0].items()
                        if key
                        not in {
                            "started_offset_seconds",
                            "completed_offset_seconds",
                        }
                    }
                    != expected_attempt
                )
            )
            or (
                not provider_neutral_v2
                and (
                    not isinstance(attempt, list)
                    or attempt != [expected_attempt]
                )
            )
            or not isinstance(captured_at, str)
            or not captured_at
            or len(captured_at.encode("utf-8")) > 128
            or "\x00" in captured_at
            or receipt.get("network_used") is not False
            or receipt.get("external_validation") != "UNTESTED"
            or receipt.get("transport_authority")
            != UNVERIFIED_TRANSPORT_AUTHORITY
            or receipt.get("scientific_evidence") is not False
            or (
                provider_neutral_v2
                and not isinstance(receipt.get("egress_budget"), Mapping)
            )
            or response_receipt_record.parent_artifacts
            != (external_request_record.sha256, raw_response_record.sha256)
        ):
            fail("captured provider response receipt is inconsistent")
        if provider_neutral_v2:
            budget = receipt["egress_budget"]
            if (
                set(budget)
                != {
                    *budget_policy,
                    "request_bytes_used",
                    "response_bytes_used",
                    "total_bytes_used",
                    "deadline_elapsed_seconds",
                    "deadline_remaining_seconds",
                    "deadline_satisfied",
                }
                or any(
                    budget.get(key) != value
                    for key, value in budget_policy.items()
                )
                or budget.get("request_bytes_used") != len(request_body_bytes)
                or budget.get("response_bytes_used") != len(raw_response_bytes)
                or budget.get("total_bytes_used")
                != len(request_body_bytes) + len(raw_response_bytes)
                or budget.get("deadline_satisfied") is not True
            ):
                fail("captured provider response budget is inconsistent")

        provider_response = json_value(
            provider_response_record, "model provider response"
        )
        raw_response_value = safe_json_loads(raw_response_bytes)
        if not isinstance(raw_response_value, Mapping):
            fail("captured raw provider response is not an object")
        exact_keys(
            provider_response,
            {
                "external_validation",
                "kind",
                "network_used",
                "raw_response_sha256",
                "request_id",
                "response",
                "schema_version",
                "scientific_evidence",
                "transport_authority",
            },
            "model provider response",
        )
        if (
            provider_response
            != {
                "schema_version": "1.0",
                "kind": "MODEL_PROVIDER_RESPONSE",
                "request_id": request_id,
                "raw_response_sha256": raw_response_sha256,
                "response": dict(raw_response_value),
                "network_used": False,
                "external_validation": "UNTESTED",
                "transport_authority": UNVERIFIED_TRANSPORT_AUTHORITY,
                "scientific_evidence": False,
            }
            or provider_response_record.parent_artifacts
            != (raw_response_record.sha256, response_receipt_record.sha256)
        ):
            fail("captured model provider response is inconsistent")

        exact_keys(
            model_output,
            {
                "capability",
                "external_validation",
                "invocation_id",
                "kind",
                "model_requested",
                "model_returned",
                "network_used",
                "output",
                "provider_id",
                "provider_response_id",
                "provider_tools",
                "schema_version",
                "scientific_evidence",
                "transport_authority",
                "usage",
            },
            "model output",
        )
        if (
            model_output.get("schema_version") != "1.0"
            or model_output.get("kind") != "MODEL_OUTPUT"
            or model_output.get("invocation_id") != invocation_id
            or model_output.get("provider_id") != provider_id
            or model_output.get("provider_response_id")
            != expected_response_id
            or model_output.get("model_requested") != model_requested
            or model_output.get("model_returned") != model_requested
            or model_output.get("capability") != "coding"
            or model_output.get("output") != provider_proposal
            or model_output.get("usage") != expected_usage
            or model_output.get("network_used") is not False
            or model_output.get("external_validation") != "UNTESTED"
            or model_output.get("transport_authority")
            != UNVERIFIED_TRANSPORT_AUTHORITY
            or model_output.get("scientific_evidence") is not False
            or model_output.get("provider_tools") is not False
            or output_record.parent_artifacts
            != (
                invocation_record.sha256,
                request_body_record.sha256,
                provider_response_record.sha256,
            )
        ):
            fail("captured model output is inconsistent")

        try:
            provider_projection = provider_contract.verify_execution(
                provider_version=external_request.get("policy_id"),
                endpoint=request_intent.get("endpoint"),
                credential_env_name=external_request.get("credential_env_name"),
                credential_present=external_request.get("credential_present"),
                invocation_id=expected_invocation_id,
                request_projection=request_projection,
                response_projection=response_projection,
                request_body_bytes=request_body_bytes,
                raw_response_bytes=raw_response_bytes,
                retained_instructions=expected_instructions,
                retained_input=expected_input_text,
                retained_schema=proposal_schema,
                maximum_output_bytes=32 * 1024 * 1024,
                network_used=receipt.get("network_used"),
                external_validation=receipt.get("external_validation"),
                transport_authority=receipt.get("transport_authority"),
                transport_execution_authority_artifact_sha256=None,
                custody_artifact_hashes=tuple(
                    item.sha256 for item in provider_parents
                ),
            )
        except ProviderVerificationError as exc:
            raise OrchestrationError(
                "vNext autonomous implementation verification failed: "
                "provider execution violates its closed verifier contract"
            ) from exc
        if provider_neutral_v2:
            assert provider_link_record is not None
            provider_link = json_value(
                provider_link_record,
                "provider admission link",
            )
            expected_provider_link = {
                "schema_version": PROVIDER_ADMISSION_LINK_SCHEMA_VERSION,
                "status": "ADMITTED",
                "reason_code": "VERIFIED_ADVISORY_PROVIDER_ACTION_LINK",
                "provider_attempt_artifact_sha256": (
                    provider_attempt_record.sha256
                ),
                "actionable_proposal_artifact_sha256": proposal_record.sha256,
                "action_validation_receipt_sha256": validation_record.sha256,
                "semantic_id": semantic_id,
                "provider": {
                    "provider_id": provider_projection.provider_id,
                    "provenance_schema_version": (
                        provider_projection.provenance_schema_version
                    ),
                    "provider_version": provider_projection.provider_version,
                    "invocation_id": provider_projection.invocation_id,
                    "request_id": provider_projection.request_id,
                    "model_requested": provider_projection.model_requested,
                    "model_returned": provider_projection.model_returned,
                    "provider_response_id": (
                        provider_projection.provider_response_id
                    ),
                    "network_used": provider_projection.network_used,
                    "external_validation": (
                        provider_projection.external_validation
                    ),
                    "transport_authority": (
                        provider_projection.transport_authority
                    ),
                    "transport_execution_authority_artifact_sha256": None,
                    "custody_artifact_hashes": list(
                        provider_projection.custody_artifact_hashes
                    ),
                    "scientific_evidence": False,
                },
                "provider_output_trust": "UNTRUSTED_ADVISORY",
                "core_action_identity": "PROVIDER_NEUTRAL",
                "scientific_evidence": False,
            }
            if (
                provider_link != expected_provider_link
                or provider_link_record.parent_artifacts
                != (
                    provider_attempt_record.sha256,
                    proposal_record.sha256,
                    validation_record.sha256,
                    *provider_projection.custody_artifact_hashes,
                )
            ):
                fail("provider admission link is inconsistent")

        selected_review = review_records[selected_template]
        if (
            registry.get_bytes(worker_record.sha256)
            is None
            or hashlib.sha256(registry.get_bytes(worker_record.sha256)).hexdigest()
            != catalog_by_template[selected_template]["worker_code_sha256"]
            or set(worker_record.parent_artifacts) != {selected_review.sha256}
        ):
            fail("worker bytes do not match the selected pinned review")
        configuration = json_value(configuration_record, "worker configuration")
        core_evidence_hashes = (
            neutral_evidence_hashes if provider_neutral_v2 else evidence_hashes
        )
        expected_configuration = {
            "schema_version": (
                WORKER_CONFIGURATION_SCHEMA_VERSION
                if provider_neutral_v2
                else LEGACY_WORKER_CONFIGURATION_SCHEMA_VERSION
            ),
            "experiment_id": object_ids.get("Experiment"),
            "hypothesis_id": "hypothesis-threshold",
            "implementation_id": implementation_id,
            "phase": "EXPLORATORY",
            "proposal_id": proposal_id,
            "proposal_artifact_sha256": proposal_record.sha256,
            "template_id": selected_template.value,
            "template_version": "1.0",
            "parameters": dict(sorted(parameter_map.items())),
            "parent_evidence_sha256s": list(core_evidence_hashes),
            "data_sha256": data_record.sha256,
            "evaluator_sha256": evaluator_record.sha256,
            "seeds": [3, 7],
        }
        if (
            configuration != expected_configuration
            or set(configuration_record.parent_artifacts)
            != {
                proposal_record.sha256,
                catalog_record.sha256,
                data_record.sha256,
                evaluator_record.sha256,
            }
        ):
            fail("compiled worker configuration is inconsistent")
        validation = json_value(validation_record, "admission receipt")
        if provider_neutral_v2:
            expected_checks = [
                "strict_normalized_action_shape",
                "reviewed_template_membership",
                "bounded_template_parameters",
                "complete_parent_evidence",
                "double_render_determinism",
                "reviewed_worker_code_hash",
                "fixed_no_shell_no_network_execution_contract",
            ]
            expected_validation = {
                "schema_version": ACTION_VALIDATION_SCHEMA_VERSION,
                "status": "ADMITTED",
                "reason_code": "REVIEWED_TEMPLATE_ACTION_ADMITTED",
                "semantic_id": semantic_id,
                "actionable_proposal_artifact_sha256": proposal_record.sha256,
                "catalog_artifact_sha256": catalog_record.sha256,
                "template_id": selected_template.value,
                "worker_code_sha256": worker_record.sha256,
                "configuration_sha256": configuration_record.sha256,
                "declared_parent_evidence_sha256s": list(core_evidence_hashes),
                "verified_parent_evidence_sha256s": list(core_evidence_hashes),
                "checks": expected_checks,
                "provider_provenance_custody": (
                    "SEPARATE_ADVISORY_LINK_REQUIRED"
                ),
                "provider_identity_included": False,
                "scientific_evidence": False,
            }
        else:
            expected_checks = [
                "exact_provider_capability",
                "exact_provider_schema",
                "strict_proposal_shape",
                "reviewed_template_membership",
                "bounded_template_parameters",
                "complete_parent_evidence",
                "double_render_determinism",
                "reviewed_worker_code_hash",
                "fixed_no_shell_no_network_execution_contract",
            ]
            expected_validation = {
                "schema_version": "AUTONOMOUS_IMPLEMENTATION_VALIDATION_V1",
                "status": "ADMITTED",
                "reason_code": "REVIEWED_TEMPLATE_ADMITTED",
                "proposal_artifact_sha256": proposal_record.sha256,
                "catalog_artifact_sha256": catalog_record.sha256,
                "template_id": selected_template.value,
                "worker_code_sha256": worker_record.sha256,
                "configuration_sha256": configuration_record.sha256,
                "declared_parent_evidence_sha256s": list(core_evidence_hashes),
                "verified_parent_evidence_sha256s": list(core_evidence_hashes),
                "checks": expected_checks,
                "provider_output_trust": "UNTRUSTED_ADVISORY",
                "scientific_evidence": False,
            }
        if (
            validation != expected_validation
            or set(validation_record.parent_artifacts)
            != {
                proposal_record.sha256,
                catalog_record.sha256,
                data_record.sha256,
                evaluator_record.sha256,
                worker_record.sha256,
                configuration_record.sha256,
            }
        ):
            fail("admission receipt is inconsistent")
        descriptor = json_value(descriptor_record, "admitted descriptor")
        expected_descriptor = {
            "schema_version": (
                DESCRIPTOR_SCHEMA_VERSION
                if provider_neutral_v2
                else LEGACY_DESCRIPTOR_SCHEMA_VERSION
            ),
            "implementation_id": implementation_id,
            "experiment_id": object_ids.get("Experiment"),
            "hypothesis_id": "hypothesis-threshold",
            "phase": "EXPLORATORY",
            "proposal_id": proposal_id,
            "template_id": selected_template.value,
            "template_version": "1.0",
            "catalog_artifact_sha256": catalog_record.sha256,
            "proposal_artifact_sha256": proposal_record.sha256,
            "worker_code_sha256": worker_record.sha256,
            "configuration_sha256": configuration_record.sha256,
            "parent_evidence_sha256s": list(core_evidence_hashes),
            "validation_receipt_sha256": validation_record.sha256,
            "execution_boundary": "FROZEN_RUN_SPEC_LOCAL_MAC_ONLY",
            "shell_allowed": False,
            "network_allowed": False,
            "scientific_evidence": False,
        }
        if provider_neutral_v2:
            expected_descriptor.update(
                {
                    "provider_provenance_custody": (
                        "SEPARATE_ADVISORY_LINK_REQUIRED"
                    ),
                    "provider_identity_included": False,
                }
            )
        else:
            expected_descriptor["provider_output_trust"] = "UNTRUSTED_ADVISORY"
        if (
            descriptor != expected_descriptor
            or set(descriptor_record.parent_artifacts)
            != {
                proposal_record.sha256,
                worker_record.sha256,
                configuration_record.sha256,
                validation_record.sha256,
                catalog_record.sha256,
                data_record.sha256,
                evaluator_record.sha256,
            }
        ):
            fail("admitted descriptor is inconsistent")
        result["artifact_graph_valid"] = True

        spec = json_value(spec_record, "frozen run spec")
        expected_spec_fields = {
            "argv",
            "attempt",
            "bytes_per_sample",
            "cache_policy",
            "checkpoint_policy",
            "code_sha256",
            "comparison_tolerance",
            "compute_profile",
            "configuration_sha256",
            "data_sha256",
            "evaluator_sha256",
            "evidence_class",
            "expected_outputs",
            "experiment_id",
            "hypothesis_id",
            "maximum_stderr_bytes",
            "maximum_stdout_bytes",
            "metadata",
            "network_allowed",
            "phase",
            "required_ablations",
            "resource_estimate",
            "retry_of_run_id",
            "run_id",
            "schema_version",
            "scientific_purpose",
            "seed_policy",
            "seeds",
            "shell_allowed",
            "termination_conditions",
            "timeout_seconds",
            "worker_overhead_bytes",
            "working_directory",
        }
        exact_keys(spec, expected_spec_fields, "frozen run spec")
        run_id = spec.get("run_id")
        expected_worker_path = (
            ".scientist-one-build/autonomous-implementation/"
            f"{worker_record.sha256}.py"
        )
        expected_spec = FrozenRunSpec(
            run_id=run_id,
            experiment_id=object_ids.get("Experiment"),
            hypothesis_id="hypothesis-threshold",
            phase=ExperimentPhase.EXPLORATORY,
            argv=(
                "/usr/bin/python3",
                "-I",
                "-S",
                "-B",
                expected_worker_path,
                "--config",
                configuration_record.path,
                "--data",
                data_record.path,
            ),
            working_directory=".",
            code_sha256=worker_record.sha256,
            data_sha256=data_record.sha256,
            configuration_sha256=configuration_record.sha256,
            evaluator_sha256=evaluator_record.sha256,
            seeds=(3, 7),
            comparison_tolerance=0.0,
            timeout_seconds=30.0,
            maximum_stdout_bytes=64 * 1024,
            maximum_stderr_bytes=64 * 1024,
            network_allowed=False,
            shell_allowed=False,
            evidence_class=EvidenceClass.NON_EVIDENTIARY,
            scientific_purpose=(
                "exercise an admitted reviewed autonomous implementation as a "
                "non-evidentiary exploratory component fixture"
            ),
            expected_outputs=("output_manifest", "seed_result"),
            seed_policy="EXPLICIT_FIXED_SEEDS_NO_SELECTION",
            termination_conditions=(
                "wall_clock_timeout",
                "all_planned_seeds_reported",
            ),
            metadata={
                "autonomous_implementation_descriptor_sha256": descriptor_record.sha256,
                "autonomous_implementation_validation_sha256": validation_record.sha256,
                "catalog_artifact_sha256": catalog_record.sha256,
                "model_output_scientific_evidence": False,
                "model_output_trust": "UNTRUSTED_ADVISORY",
            },
        )
        if (
            not isinstance(run_id, str)
            or object_ids.get("Run") != run_id
            or dict(spec) != expected_spec.to_dict()
            or set(spec_record.parent_artifacts)
            != {
                descriptor_record.sha256,
                validation_record.sha256,
                worker_record.sha256,
                configuration_record.sha256,
                data_record.sha256,
                evaluator_record.sha256,
            }
        ):
            fail("frozen spec does not reconstruct the admitted execution")
        spec_sha256 = hashlib.sha256(canonical_json_bytes(dict(spec))).hexdigest()
        job_id = f"local-{spec_sha256[:20]}"

        plan = json_value(plan_record, "adaptive execution plan")
        try:
            typed_plan = AdaptiveExecutionPlan.from_mapping(plan)
        except Exception as exc:
            raise OrchestrationError(
                "vNext autonomous implementation verification failed: "
                "adaptive execution plan cannot be rehydrated"
            ) from exc
        expected_plan = plan_adaptive_execution(
            expected_spec.compute_profile,
            expected_spec.resource_estimate,
            observed_available_memory_bytes=2 * 1024**3,
            pending_tasks=len(expected_spec.seeds),
            bytes_per_sample=expected_spec.bytes_per_sample,
            worker_overhead_bytes=expected_spec.worker_overhead_bytes,
            concurrency_cap=1,
        )
        if typed_plan != expected_plan or set(plan_record.parent_artifacts):
            fail("deduplicated adaptive execution plan unexpectedly has parents")
        manifest = json_value(manifest_record, "output manifest")
        try:
            typed_manifest = OutputManifest.from_mapping(manifest)
        except Exception as exc:
            raise OrchestrationError(
                "vNext autonomous implementation verification failed: "
                "output manifest cannot be rehydrated"
            ) from exc
        if (
            typed_manifest.run_id != run_id
            or typed_manifest.spec_sha256 != spec_sha256
            or typed_manifest.code_sha256 != worker_record.sha256
            or typed_manifest.data_sha256 != data_record.sha256
            or typed_manifest.configuration_sha256 != configuration_record.sha256
            or typed_manifest.evaluator_sha256 != evaluator_record.sha256
            or typed_manifest.planned_seeds != (3, 7)
            or typed_manifest.ablations
            or len(typed_manifest.seed_results) != 2
            or len(typed_manifest.artifacts) != 2
            or set(manifest_record.parent_artifacts) != {spec_record.sha256}
        ):
            fail("output manifest differs from the frozen autonomous run")
        plan_binding = json_value(plan_binding_record, "execution plan binding")
        try:
            plan_binding_arguments = {
                "value": plan_binding,
                "encoded": registry.get_bytes(plan_binding_record.sha256),
                "parent_artifacts": plan_binding_record.parent_artifacts,
                "run_id": run_id,
                "spec_artifact_sha256": spec_record.sha256,
                "spec_sha256": spec_sha256,
                "execution_plan_artifact_sha256": plan_record.sha256,
                "execution_plan_sha256": typed_plan.sha256,
                "manifest_artifact_sha256": manifest_record.sha256,
                "returned_artifact_sha256s": tuple(
                    item.sha256 for item in typed_manifest.artifacts
                ),
            }
            if provider_neutral_v2:
                assert input_binding_record is not None
                _validate_vnext_adaptive_plan_binding(
                    **plan_binding_arguments,
                    registry=registry,
                    execution_input_binding_artifact_sha256=(
                        input_binding_record.sha256
                    ),
                    frozen_spec=expected_spec,
                )
            else:
                _validate_vnext_adaptive_plan_binding_v1(
                    **plan_binding_arguments,
                )
        except OrchestrationError as exc:
            fail(str(exc))

        output_records_by_hash: dict[str, Any] = {}
        output_seeds_by_hash: dict[str, int] = {}
        output_payloads: dict[int, Mapping[str, Any]] = {}
        reported_metrics: list[dict[str, object]] = []
        for output in typed_manifest.artifacts:
            output_record = record(
                output.sha256,
                f"autonomous output {output.path}",
                logical_type="experiment_output.autonomous_variant_result",
                creator_role=Role.EXPERIMENT_RUNNER,
            )
            if (
                output.logical_type != "autonomous_variant_result"
                or output_record.size != output.size
                or set(output_record.parent_artifacts)
                != {manifest_record.sha256, spec_record.sha256}
            ):
                fail("promoted output differs from its manifest descriptor")
            payload = json_value(
                output_record,
                f"autonomous output {output.path}",
                canonical_newline=False,
            )
            exact_keys(
                payload,
                {
                    "experiment_id",
                    "hypothesis_id",
                    "implementation_id",
                    "metric",
                    "phase",
                    "proposal_artifact_sha256",
                    "seed",
                    "template_id",
                },
                "autonomous seed output",
            )
            seed = payload.get("seed")
            metric = payload.get("metric")
            if (
                isinstance(seed, bool)
                or seed not in {3, 7}
                or seed in output_payloads
                or isinstance(metric, bool)
                or not isinstance(metric, (int, float))
                or not math.isfinite(float(metric))
                or payload.get("experiment_id") != object_ids.get("Experiment")
                or payload.get("hypothesis_id") != "hypothesis-threshold"
                or payload.get("implementation_id") != implementation_id
                or payload.get("phase") != "EXPLORATORY"
                or payload.get("proposal_artifact_sha256") != proposal_record.sha256
                or payload.get("template_id") != selected_template.value
            ):
                fail("autonomous seed output context is invalid")
            output_records_by_hash[output_record.sha256] = output_record
            output_seeds_by_hash[output_record.sha256] = int(seed)
            output_payloads[int(seed)] = payload
        if (
            set(output_payloads) != {3, 7}
            or set(output_seeds_by_hash) != set(output_records_by_hash)
        ):
            fail("autonomous seed outputs are incomplete")
        seed_result_artifacts: set[str] = set()
        for seed_result in typed_manifest.seed_results:
            if (
                seed_result.seed not in output_payloads
                or seed_result.status.value != "SUCCESS"
                or seed_result.artifact_sha256 not in output_records_by_hash
                or output_seeds_by_hash.get(seed_result.artifact_sha256)
                != seed_result.seed
                or seed_result.artifact_sha256 in seed_result_artifacts
                or seed_result.metric is None
                or not math.isclose(
                    float(seed_result.metric),
                    float(output_payloads[seed_result.seed]["metric"]),
                    rel_tol=0.0,
                    abs_tol=1e-12,
                )
            ):
                fail("manifest seed result differs from the bound output")
            seed_result_artifacts.add(seed_result.artifact_sha256)
            reported_metrics.append(
                {"seed": seed_result.seed, "metric": float(seed_result.metric)}
            )
        if seed_result_artifacts != set(output_records_by_hash):
            fail("manifest seed results omit a promoted output")

        execution_receipt = json_value(
            execution_receipt_record, "execution receipt"
        )
        execution_receipt_fields = {
            "backend_id",
            "execution_plan_sha256",
            "frozen_run_spec_artifact_sha256",
            "frozen_run_spec_sha256",
            "implementation_descriptor_sha256",
            "job_id",
            "manifest_sha256",
            "network_isolation_attested",
            "network_use_status",
            "network_used",
            "schema_version",
            "scientific_evidence",
            "state",
            "validation_status",
        }
        if provider_neutral_v2:
            execution_receipt_fields.add("execution_input_binding_sha256")
        exact_keys(
            execution_receipt,
            execution_receipt_fields,
            "execution receipt",
        )
        if (
            execution_receipt.get("schema_version")
            != "AUTONOMOUS_IMPLEMENTATION_RUN_RECEIPT_V1"
            or execution_receipt.get("implementation_descriptor_sha256")
            != descriptor_record.sha256
            or execution_receipt.get("frozen_run_spec_sha256") != spec_sha256
            or execution_receipt.get("frozen_run_spec_artifact_sha256")
            != spec_record.sha256
            or execution_receipt.get("backend_id") != "local-mac"
            or execution_receipt.get("job_id") != job_id
            or execution_receipt.get("state") != "SUCCEEDED"
            or execution_receipt.get("validation_status") != "VALIDATED_LOCAL"
            or execution_receipt.get("network_used") is not False
            or execution_receipt.get("network_use_status")
            != "UNKNOWN_UNATTESTED"
            or execution_receipt.get("network_isolation_attested") is not False
            or execution_receipt.get("scientific_evidence") is not False
            or execution_receipt.get("manifest_sha256") != manifest_record.sha256
            or execution_receipt.get("execution_plan_sha256") != typed_plan.sha256
            or (
                provider_neutral_v2
                and (
                    input_binding_record is None
                    or execution_receipt.get("execution_input_binding_sha256")
                    != input_binding_record.sha256
                )
            )
            or set(execution_receipt_record.parent_artifacts)
            != {
                spec_record.sha256,
                descriptor_record.sha256,
                validation_record.sha256,
            }
        ):
            fail("execution receipt is not fail-closed or is misbound")
        result["execution_binding_valid"] = True

        values = [float(value) for value in selected_values]
        if selected_template is ReviewedWorkerTemplate.AFFINE_MEAN_V1:
            recomputed_metric = (
                sum(values) / len(values)
            ) * parameter_map["scale"] + parameter_map["bias"]
        else:
            recomputed_metric = (
                sum(value >= parameter_map["threshold"] for value in values)
                / len(values)
            ) * parameter_map["positive_weight"]
        if not math.isfinite(recomputed_metric):
            fail("recomputed autonomous metric is non-finite")
        if any(
            not math.isclose(
                float(payload["metric"]),
                recomputed_metric,
                rel_tol=0.0,
                abs_tol=1e-12,
            )
            for payload in output_payloads.values()
        ):
            fail("autonomous output differs from deterministic recomputation")
        semantic = json_value(semantic_record, "semantic validation")
        expected_semantic = {
            "schema_version": "AUTONOMOUS_IMPLEMENTATION_SEMANTIC_VALIDATION_V1",
            "status": "PASS",
            "template_id": selected_template.value,
            "implementation_id": implementation_id,
            "experiment_id": object_ids.get("Experiment"),
            "hypothesis_id": "hypothesis-threshold",
            "phase": "EXPLORATORY",
            "run_id": run_id,
            "data_artifact_sha256": data_record.sha256,
            "data_derivation_artifact_sha256": derivation_record.sha256,
            "configuration_artifact_sha256": configuration_record.sha256,
            "evaluator_artifact_sha256": evaluator_record.sha256,
            "descriptor_artifact_sha256": descriptor_record.sha256,
            "frozen_run_spec_artifact_sha256": spec_record.sha256,
            "execution_plan_artifact_sha256": plan_record.sha256,
            "execution_plan_binding_artifact_sha256": plan_binding_record.sha256,
            "output_manifest_artifact_sha256": manifest_record.sha256,
            "execution_receipt_artifact_sha256": execution_receipt_record.sha256,
            "seed_output_artifact_sha256s": [
                item.artifact_sha256 for item in typed_manifest.seed_results
            ],
            "planned_seeds": [3, 7],
            "recomputed_metric": recomputed_metric,
            "reported_seed_metrics": reported_metrics,
            "checks": [
                "derived_data_matches_frozen_source",
                "configuration_matches_admitted_proposal",
                "manifest_matches_frozen_spec",
                "seed_outputs_match_manifest",
                "template_metric_recomputed",
                "network_evidence_status_fail_closed",
            ],
            "network_use_status": "UNKNOWN_UNATTESTED",
            "scientific_evidence": False,
        }
        if provider_neutral_v2:
            assert input_binding_record is not None
            expected_semantic["execution_input_binding_artifact_sha256"] = (
                input_binding_record.sha256
            )
        semantic_parents = {
            derivation_record.sha256,
            data_record.sha256,
            evaluator_record.sha256,
            descriptor_record.sha256,
            configuration_record.sha256,
            spec_record.sha256,
            plan_record.sha256,
            plan_binding_record.sha256,
            manifest_record.sha256,
            execution_receipt_record.sha256,
            *output_records_by_hash,
        }
        if provider_neutral_v2:
            assert input_binding_record is not None
            semantic_parents.add(input_binding_record.sha256)
        if (
            semantic != expected_semantic
            or set(semantic_record.parent_artifacts) != semantic_parents
        ):
            fail("semantic validation receipt is not the exact recomputation")
        result["semantic_recomputation_valid"] = True
        result["scientific_evidence"] = False

        log_descriptors: dict[str, Any] = {}
        for item in registry_records.values():
            if (
                item.logical_type != "experiment_log_descriptor"
                or spec_record.sha256 not in item.parent_artifacts
            ):
                continue
            value = json_value(item, "experiment log descriptor")
            if value.get("run_id") != run_id:
                continue
            stream = value.get("stream")
            raw_hash = value.get("raw_artifact_hash")
            if stream not in {"stdout", "stderr"} or stream in log_descriptors:
                fail("autonomous log descriptors are ambiguous")
            raw_record = record(
                raw_hash,
                f"raw {stream} log",
                logical_type="raw_experiment_log_bytes",
                creator_role=Role.EXPERIMENT_RUNNER,
                mime_type="application/octet-stream",
            )
            if (
                set(item.parent_artifacts)
                != {raw_record.sha256, spec_record.sha256}
                or value.get("byte_count") != raw_record.size
            ):
                fail("autonomous log descriptor is misbound")
            log_descriptors[str(stream)] = item
        if set(log_descriptors) != {"stdout", "stderr"}:
            fail("autonomous run lacks complete log descriptors")
        captured_hashes = {
            spec_record.sha256,
            plan_record.sha256,
            plan_binding_record.sha256,
            manifest_record.sha256,
            *output_records_by_hash,
            *(item.sha256 for item in log_descriptors.values()),
        }
        if input_binding_record is not None:
            captured_hashes.add(input_binding_record.sha256)
        promotion_events = [
            (index, event)
            for index, event in enumerate(events)
            if event.metadata.get("promotion") == "EXPERIMENT_OUTPUTS_REGISTERED"
            and event.metadata.get("experiment_run_id") == run_id
        ]
        phase_events = [
            (index, event)
            for index, event in enumerate(events)
            if event.metadata.get("phase") == "AUTONOMOUS_IMPLEMENTATION"
        ]
        if len(promotion_events) != 1 or len(phase_events) != 1:
            fail("autonomous ledger checkpoints are absent or ambiguous")
        promotion_index, promotion_event = promotion_events[0]
        phase_index, phase_event = phase_events[0]
        required_phase_hashes = {
            *artifacts.values(),
            *output_records_by_hash,
            invocation_record.sha256,
            output_record.sha256,
            *(item.sha256 for item in review_records.values()),
        }
        if (
            promotion_index >= phase_index
            or promotion_event.actor_role is not Role.EXPERIMENT_RUNNER
            or set(promotion_event.artifact_hashes) != captured_hashes
            or promotion_event.random_seeds != (3, 7)
            or promotion_event.metadata.get("scientific_evidence_eligible")
            is not False
            or phase_event.actor_role is not Role.IMPLEMENTER
            or not required_phase_hashes.issubset(phase_event.artifact_hashes)
            or phase_event.random_seeds != (3, 7)
            or phase_event.metadata.get("scientific_evidence_eligible") is not False
            or phase_event.metadata.get("model_output_scientific_evidence")
            is not False
            or phase_event.metadata.get("os_enforced_sandbox") is not False
            or phase_event.metadata.get("network_used") is not False
            or phase_event.metadata.get("network_use_status")
            != "UNKNOWN_UNATTESTED"
        ):
            fail("autonomous ledger order or non-evidence binding is invalid")
        result["ledger_binding_valid"] = True

        expected_ids = {
            "Dataset": "dataset-autonomous-component-fixture",
            "Metric": "metric-autonomous-template-scalar",
            "Method": f"method-autonomous-{selected_template.value}",
            "Implementation": implementation_id,
            "Experiment": configuration["experiment_id"],
            "Run": run_id,
            "Result": "result-autonomous-component-fixture",
        }
        if dict(object_ids) != expected_ids:
            fail("summary canonical object identities are inconsistent")
        objects_by_identity = {
            (item.object_type, item.object_id): item for item in research_objects
        }
        try:
            auto_dataset = objects_by_identity[("Dataset", expected_ids["Dataset"])]
            auto_metric = objects_by_identity[("Metric", expected_ids["Metric"])]
            auto_method = objects_by_identity[("Method", expected_ids["Method"])]
            auto_implementation = objects_by_identity[
                ("Implementation", expected_ids["Implementation"])
            ]
            auto_experiment = objects_by_identity[
                ("Experiment", expected_ids["Experiment"])
            ]
            auto_run = objects_by_identity[("Run", expected_ids["Run"])]
            auto_result = objects_by_identity[("Result", expected_ids["Result"])]
            main_hypothesis = objects_by_identity[("Hypothesis", "hypothesis-threshold")]
        except KeyError as exc:
            raise OrchestrationError(
                "vNext autonomous implementation verification failed: "
                "canonical autonomous state is incomplete"
            ) from exc

        def parents(item: Any) -> set[tuple[str, str, str, bool]]:
            return {
                (
                    parent.object_type,
                    parent.object_id,
                    parent.relation,
                    parent.evaluated,
                )
                for parent in item.parents
            }

        def non_evidentiary(item: Any) -> bool:
            return bool(
                item.metadata.get("evidence_use") == "NON_EVIDENTIARY"
                and item.metadata.get("scientific_evidence_eligible") is False
            )

        expected_run_outputs = {
            *captured_hashes,
            execution_receipt_record.sha256,
        }
        if provider_neutral_v2:
            provider_specific_hashes = {
                provider_attempt_record.sha256,
                *(item.sha256 for item in provider_parents),
                *(
                    (provider_link_record.sha256,)
                    if provider_link_record is not None
                    else ()
                ),
            }
            provider_specific_text = {
                provider_projection.provider_id,
                provider_projection.provider_version,
                provider_projection.request_id,
                provider_projection.provider_response_id,
            }
            neutral_core_objects = (
                auto_method,
                auto_implementation,
                auto_experiment,
                auto_run,
                auto_result,
            )
            if any(
                any(
                    value.encode("utf-8") in item.canonical_bytes()
                    for value in (*provider_specific_hashes, *provider_specific_text)
                )
                for item in neutral_core_objects
            ):
                fail(
                    "canonical autonomous core embeds provider-specific provenance"
                )
        if (
            not all(
                non_evidentiary(item)
                for item in (
                    auto_dataset,
                    auto_metric,
                    auto_method,
                    auto_implementation,
                    auto_experiment,
                    auto_run,
                    auto_result,
                )
            )
            or tuple(auto_dataset.artifact_hashes)
            != (data_record.sha256, derivation_record.sha256)
            or parents(auto_dataset)
            != {
                ("Dataset", "dataset-vnext-fixture", "derived_from", True),
                ("Split", "development", "selected_from", True),
            }
            or auto_metric.direction.value != "HIGHER_IS_BETTER"
            or auto_metric.evidence_level.value != "PROXY"
            or parents(auto_metric)
            != {
                ("Dataset", expected_ids["Dataset"], "defined_on", True),
            }
            or parents(auto_method)
            != {("Hypothesis", "hypothesis-threshold", "explores", True)}
            or auto_implementation.method_id != expected_ids["Method"]
            or tuple(auto_implementation.code_artifact_hashes)
            != (worker_record.sha256,)
            or tuple(auto_implementation.configuration_artifact_hashes)
            != (
                configuration_record.sha256,
                descriptor_record.sha256,
                validation_record.sha256,
            )
            or parents(auto_implementation)
            != {("Method", expected_ids["Method"], "implements", True)}
            or tuple(auto_experiment.hypothesis_ids) != ("hypothesis-threshold",)
            or auto_experiment.implementation_id != implementation_id
            or tuple(auto_experiment.dataset_ids) != (expected_ids["Dataset"],)
            or tuple(auto_experiment.split_ids) != ("development",)
            or tuple(auto_experiment.metric_ids) != (expected_ids["Metric"],)
            or tuple(auto_experiment.baseline_ids) != ()
            or tuple(auto_experiment.configuration_artifact_hashes)
            != (
                configuration_record.sha256,
                descriptor_record.sha256,
                evaluator_record.sha256,
            )
            or auto_experiment.compute_profile.value != "LOCAL_MAC"
            or parents(auto_experiment)
            != {
                ("Hypothesis", "hypothesis-threshold", "explores", True),
                (
                    "Implementation",
                    implementation_id,
                    "uses",
                    True,
                ),
                ("Dataset", expected_ids["Dataset"], "uses", True),
                ("Split", "development", "binds_split", True),
                ("Metric", expected_ids["Metric"], "evaluates", True),
            }
            or auto_run.experiment_id != expected_ids["Experiment"]
            or auto_run.configuration_artifact_hash != configuration_record.sha256
            or tuple(auto_run.random_seeds) != (3, 7)
            or set(auto_run.output_artifact_hashes) != expected_run_outputs
            or parents(auto_run)
            != {("Experiment", expected_ids["Experiment"], "executes", True)}
            or tuple(auto_result.run_ids) != (run_id,)
            or auto_result.metric_id != expected_ids["Metric"]
            or auto_result.direction.value != "HIGHER_IS_BETTER"
            or not isinstance(auto_result.value, (int, float))
            or not math.isclose(
                float(auto_result.value),
                recomputed_metric,
                rel_tol=0.0,
                abs_tol=1e-12,
            )
            or set(auto_result.source_artifact_hashes)
            != set(output_records_by_hash)
            or set(auto_result.evaluation_artifact_hashes)
            != {
                manifest_record.sha256,
                semantic_record.sha256,
                evaluator_record.sha256,
                execution_receipt_record.sha256,
            }
            or parents(auto_result)
            != {
                ("Run", run_id, "aggregates", True),
                ("Metric", expected_ids["Metric"], "reports", True),
            }
            or tuple(main_hypothesis.planned_experiment_ids)
            != ("experiment-threshold-fixture",)
        ):
            fail("canonical autonomous state does not bind the verified run")
        result["canonical_state_binding_valid"] = True

        autonomous_hashes = {
            *artifacts.values(),
            *output_records_by_hash,
            worker_record.sha256,
        }
        autonomous_ids = set(expected_ids.values())

        def recursively_contains_autonomous(value: object) -> bool:
            if isinstance(value, str):
                return value in autonomous_hashes or value in autonomous_ids
            if isinstance(value, Mapping):
                return any(
                    recursively_contains_autonomous(child)
                    for child in value.values()
                )
            if isinstance(value, (list, tuple, set, frozenset)):
                return any(recursively_contains_autonomous(child) for child in value)
            return False

        forbidden_state_types = {
            "Ablation",
            "Claim",
            "Decision",
            "Evidence",
            "StatisticalTest",
            "VenueAssessment",
        }
        for item in research_objects:
            if item.object_type not in forbidden_state_types:
                continue
            if any(parent.object_id == expected_ids["Result"] for parent in item.parents):
                fail("autonomous result entered a scientific canonical dependency")
            state_payload = item.to_dict()
            # Metadata may truthfully name fixture limitations, so inspect only
            # authoritative fields and parent relationships here.
            state_payload.pop("metadata", None)
            if recursively_contains_autonomous(state_payload):
                fail("autonomous run entered a scientific canonical authority")

        claim_graph_records = [
            item
            for item in registry_records.values()
            if item.logical_type == "claim_evidence_graph"
        ]
        paper_bundle_records = [
            item
            for item in registry_records.values()
            if item.logical_type == "authoritative_research_bundle"
        ]
        paper_candidate_records = [
            item
            for item in registry_records.values()
            if item.logical_type == "paper_candidate"
        ]
        if (
            len(claim_graph_records) != 1
            or len(paper_bundle_records) != 1
            or len(paper_candidate_records) != 1
        ):
            fail("claim or paper authorities are absent or ambiguous")
        for item, label in (
            (claim_graph_records[0], "claim graph"),
            (paper_bundle_records[0], "authoritative paper bundle"),
            (paper_candidate_records[0], "paper candidate"),
        ):
            value = json_value(item, label)
            if recursively_contains_autonomous(value):
                fail(f"{label} consumed non-evidentiary autonomous output")
        result["claim_paper_exclusion_valid"] = True

        if not {
            execution_receipt_record.sha256,
            semantic_record.sha256,
        }.issubset(summary_record.parent_artifacts):
            fail("final summary does not parent autonomous execution authorities")
        result["valid"] = True

    def _verify_vnext_fixture(
        self,
        run_id: str,
        operation: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Verify only the authorities actually materialized by a vNext fixture."""

        operation_status = str(operation["status"])
        launch_mode = str(operation["launch_mode"])
        result: dict[str, Any] = {
            "schema_version": VNEXT_VERIFICATION_SCHEMA_VERSION,
            "kind": "RESEARCH_OS_FIXTURE_VERIFICATION",
            "run_id": run_id,
            "status": "FAIL",
            "operation": {
                "receipt_valid": True,
                "status": operation_status,
                "recovery_policy": operation["recovery_policy"],
            },
            "artifact_registry": {
                "valid": False,
                "records": 0,
                "receipt_binding_valid": False,
                "ledger_closure_valid": False,
            },
            "event_ledger": {
                "valid": False,
                "event_count": 0,
                "head_hash": None,
                "receipt_binding_valid": False,
                "run_identity_valid": False,
                "artifact_references_valid": False,
            },
            "summary": {
                "valid": False,
                "artifact_sha256": operation.get("summary_artifact_sha256"),
                "final_event_binding_valid": False,
            },
            "canonical_research_state": {
                "valid": False,
                "object_count": 0,
                "object_type_count": 0,
                "non_evidentiary_reproduction_valid": False,
                "summary_binding_valid": False,
            },
            "autonomous_implementation": {
                "valid": False,
                "summary_binding_valid": False,
                "artifact_graph_valid": False,
                "execution_binding_valid": False,
                "semantic_recomputation_valid": False,
                "ledger_binding_valid": False,
                "canonical_state_binding_valid": False,
                "claim_paper_exclusion_valid": False,
                "network_use_status": None,
                "scientific_evidence": False,
                "provider_neutral": False,
                "provider_neutrality_schema": None,
                "historical_v1_replay": False,
                "current_production_eligible": False,
            },
            "scientific_soundness_authority": {
                "valid": False,
                "artifact_sha256": None,
                "claim_graph_artifact_sha256": None,
                "central_claim_ids": [],
                "verdict": None,
            },
            "scientific_timeline_authority": {
                "valid": False,
                "receipt_count": 0,
                "receipts": [],
                "scientific_evidence": False,
            },
            "launch_provenance": {
                "mode": launch_mode,
                "guarded_launch_receipt_sha256": operation.get(
                    "guarded_launch_receipt_sha256"
                ),
                "declaration_valid": False,
                "receipt_valid": False,
                "source_snapshot_binding_valid": False,
                "guarded_production_launch_valid": False,
            },
            "restart_lineage": {
                "required": (
                    operation.get("schema_version")
                    == VNEXT_RESTART_OPERATION_SCHEMA_VERSION
                ),
                "receipt_sha256": operation.get(
                    "restart_lineage_receipt_sha256"
                ),
                "abandoned_run_id": operation.get("restart_from_run_id"),
                "receipt_valid": False,
                "registry_binding_valid": False,
                "summary_binding_valid": False,
                "valid": False,
                "status": (
                    "UNVERIFIED"
                    if operation.get("schema_version")
                    == VNEXT_RESTART_OPERATION_SCHEMA_VERSION
                    else "NOT_APPLICABLE"
                ),
            },
            "completion_authorities_valid": False,
            "production_completion_valid": False,
            "system_fixture_integrity": "NOT_ESTABLISHED",
            "scientific_evidence_established": False,
            "resume_supported": False,
            "reproduce_supported": False,
            "package_supported": False,
            "issues": [],
        }
        issues = result["issues"]
        guarded_launch_receipt: dict[str, Any] | None = None
        restart_lineage_receipt: dict[str, Any] | None = None
        try:
            guarded_launch_receipt = self._guarded_launch_receipt(
                run_id, operation
            )
            result["launch_provenance"]["declaration_valid"] = True
            result["launch_provenance"]["receipt_valid"] = (
                guarded_launch_receipt is not None
            )
        except Exception as exc:
            issues.append(f"GUARDED_LAUNCH_INVALID: {type(exc).__name__}: {exc}")
        try:
            restart_lineage_receipt = self._restart_lineage_receipt(
                run_id,
                operation,
            )
            result["restart_lineage"]["receipt_valid"] = (
                restart_lineage_receipt is not None
            )
            if restart_lineage_receipt is None:
                result["restart_lineage"]["valid"] = True
        except Exception as exc:
            issues.append(
                f"RESTART_LINEAGE_INVALID: {type(exc).__name__}: {exc}"
            )
        if operation_status != "COMPLETE":
            issues.append(f"OPERATION_{operation_status}")
            return result

        try:
            registry_receipt = operation["artifact_registry"]
            ledger_receipt = operation["event_ledger"]
            registry = ArtifactRegistry(
                self.root, f"runs/{run_id}/registry"
            )
            ledger = EventLedger(
                self.root, f"runs/{run_id}/events.jsonl"
            )
            registry_validation = registry.verify_all(raise_on_error=True)
            ledger_validation = ledger.validate(raise_on_error=True)
            records = registry_validation.records
            events = ledger_validation.events
            registry_records = {record.sha256: record for record in records}

            registry_receipt_valid = (
                registry_validation.valid
                and registry_validation.count == registry_receipt["artifact_count"]
                and registry.base_path.as_posix() == registry_receipt["base_path"]
                and all(
                    record.frozen and record.validation_result == "PASS"
                    for record in records
                )
            )
            result["artifact_registry"].update(
                {
                    "valid": registry_validation.valid,
                    "records": registry_validation.count,
                    "receipt_binding_valid": registry_receipt_valid,
                }
            )

            ledger_receipt_valid = (
                ledger_validation.valid
                and ledger_validation.event_count == ledger_receipt["event_count"]
                and ledger_validation.head_hash == ledger_receipt["head_hash"]
                and ledger.relative_path.as_posix() == ledger_receipt["path"]
            )
            run_identity_valid = bool(events) and all(
                event.run_id == run_id for event in events
            )
            artifact_references_valid = bool(events) and all(
                digest in registry_records
                for event in events
                for digest in event.artifact_hashes
            )
            result["event_ledger"].update(
                {
                    "valid": ledger_validation.valid,
                    "event_count": ledger_validation.event_count,
                    "head_hash": ledger_validation.head_hash,
                    "receipt_binding_valid": ledger_receipt_valid,
                    "run_identity_valid": run_identity_valid,
                    "artifact_references_valid": artifact_references_valid,
                }
            )

            roots = {
                digest
                for event in events
                for digest in event.artifact_hashes
            }
            closure: set[str] = set()
            pending = list(roots)
            closure_valid = artifact_references_valid
            while pending and closure_valid:
                digest = pending.pop()
                if digest in closure:
                    continue
                record = registry_records.get(digest)
                if record is None:
                    closure_valid = False
                    break
                closure.add(digest)
                pending.extend(record.parent_artifacts)
            closure_valid = closure_valid and closure == set(registry_records)
            result["artifact_registry"]["ledger_closure_valid"] = closure_valid

            if guarded_launch_receipt is not None:
                source_snapshots = tuple(
                    record
                    for record in records
                    if record.logical_type == "vnext_source_snapshot"
                )
                if len(source_snapshots) != 1:
                    raise OrchestrationError(
                        "vNext guarded launch source snapshot is absent or ambiguous"
                    )
                source_snapshot = safe_json_loads(
                    registry.get_bytes(source_snapshots[0].sha256)
                )
                if (
                    not isinstance(source_snapshot, dict)
                    or set(source_snapshot)
                    != {"captured_at", "files", "fixture_notice", "schema_version"}
                    or source_snapshot.get("schema_version")
                    != "SCIENTIST_ONE_VNEXT_SOURCE_SNAPSHOT_V1"
                    or source_snapshot.get("fixture_notice") != VNEXT_FIXTURE_NOTICE
                    or not isinstance(source_snapshot.get("files"), list)
                ):
                    raise OrchestrationError(
                        "vNext guarded launch source snapshot is malformed"
                    )
                snapshot_entries: list[tuple[str, str]] = []
                snapshot_paths: set[str] = set()
                for entry in source_snapshot["files"]:
                    if (
                        not isinstance(entry, dict)
                        or set(entry) != {"path", "sha256"}
                        or not isinstance(entry.get("path"), str)
                        or not isinstance(entry.get("sha256"), str)
                        or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
                        is None
                        or entry["path"] in snapshot_paths
                    ):
                        raise OrchestrationError(
                            "vNext guarded launch source snapshot entry is invalid"
                        )
                    snapshot_paths.add(entry["path"])
                    snapshot_entries.append((entry["path"], entry["sha256"]))
                captured_inventory = guarded_launch_receipt[
                    "captured_source_inventory"
                ]
                captured_entries = [
                    (entry["path"], entry["sha256"])
                    for entry in captured_inventory["entries"]
                    if entry["path"] != "scripts/scientist_one_cli.py"
                ]
                source_snapshot_binding_valid = (
                    bool(snapshot_entries)
                    and snapshot_entries == captured_entries
                )
                result["launch_provenance"][
                    "source_snapshot_binding_valid"
                ] = source_snapshot_binding_valid
                result["launch_provenance"][
                    "guarded_production_launch_valid"
                ] = source_snapshot_binding_valid

            summary_hash = str(operation["summary_artifact_sha256"])
            summary_record = registry_records.get(summary_hash)
            if (
                summary_record is None
                or summary_record.logical_type != "research_os_run_summary"
                or summary_record.mime_type != "application/json"
            ):
                raise OrchestrationError(
                    "vNext fixture summary artifact is absent or mistyped"
                )
            summary_value = safe_json_loads(registry.get_bytes(summary_hash))
            if not isinstance(summary_value, dict):
                raise OrchestrationError(
                    "vNext fixture summary artifact is malformed"
                )
            if restart_lineage_receipt is not None:
                lineage_records = tuple(
                    record
                    for record in records
                    if record.logical_type == "guarded_restart_lineage"
                )
                if len(lineage_records) != 1:
                    raise OrchestrationError(
                        "vNext restart lineage registry authority is ambiguous"
                    )
                lineage_record = lineage_records[0]
                lineage_bytes = registry.get_bytes(lineage_record.sha256)
                lineage_summary = summary_value.get("restart_lineage")
                lineage_registry_valid = (
                    lineage_bytes == _canonical_bytes(restart_lineage_receipt)
                    and lineage_record.creator_role == Role.ORCHESTRATOR
                    and lineage_record.parent_artifacts == ()
                    and lineage_record.frozen
                    and lineage_record.validation_result == "PASS"
                )
                lineage_summary_valid = (
                    isinstance(lineage_summary, dict)
                    and set(lineage_summary)
                    == {
                        "abandoned_run_id",
                        "artifact_sha256",
                        "protected_resources_reused",
                        "recovery_semantics",
                        "scientific_authority",
                    }
                    and lineage_summary.get("abandoned_run_id")
                    == restart_lineage_receipt["abandoned_run_id"]
                    and lineage_summary.get("artifact_sha256")
                    == lineage_record.sha256
                    and lineage_summary.get("protected_resources_reused")
                    is False
                    and lineage_summary.get("recovery_semantics")
                    == "NEW_RUN_NO_SAME_ID_RESUME"
                    and lineage_summary.get("scientific_authority") is False
                    and lineage_record.sha256
                    in summary_record.parent_artifacts
                )
                result["restart_lineage"].update(
                    {
                        "registry_binding_valid": lineage_registry_valid,
                        "summary_binding_valid": lineage_summary_valid,
                        "valid": lineage_registry_valid
                        and lineage_summary_valid,
                        "status": (
                            "VERIFIED_NEW_RUN_LINEAGE"
                            if lineage_registry_valid and lineage_summary_valid
                            else "INVALID"
                        ),
                    }
                )
            else:
                lineage_records = tuple(
                    record
                    for record in records
                    if record.logical_type == "guarded_restart_lineage"
                )
                if lineage_records or "restart_lineage" in summary_value:
                    raise OrchestrationError(
                        "non-restart vNext fixture has registry restart lineage"
                    )
            from .scientific_design import (
                ExperimentStage,
                ScientificTimelineReceipt,
                require_scientific_timeline_receipt,
            )

            timeline_records = tuple(
                record
                for record in records
                if record.logical_type == "scientific_timeline_receipt"
            )
            if len(timeline_records) != 2:
                raise OrchestrationError(
                    "vNext fixture requires exactly two scientific timeline receipts"
                )
            timeline_values: list[dict[str, Any]] = []
            timeline_receipts: list[Any] = []
            for timeline_record in timeline_records:
                timeline_value = safe_json_loads(
                    registry.get_bytes(timeline_record.sha256)
                )
                if not isinstance(timeline_value, dict):
                    raise OrchestrationError(
                        "vNext scientific timeline receipt is malformed"
                    )
                receipt = ScientificTimelineReceipt.from_dict(timeline_value)
                resolved = require_scientific_timeline_receipt(
                    registry,
                    ledger,
                    receipt_artifact_sha256=timeline_record.sha256,
                    run_id=run_id,
                    contract_artifact_sha256=(
                        receipt.contract_artifact_sha256
                    ),
                    experiment_plan_artifact_sha256s=(
                        receipt.experiment_plan_artifact_sha256s
                    ),
                    frozen_run_spec_artifact_sha256=(
                        receipt.frozen_run_spec_artifact_sha256
                    ),
                    output_manifest_artifact_sha256=(
                        receipt.output_manifest_artifact_sha256
                    ),
                )
                if resolved != receipt:
                    raise OrchestrationError(
                        "vNext scientific timeline receipt changed on replay"
                    )
                timeline_receipts.append(receipt)
                timeline_values.append(
                    {
                        "artifact_sha256": timeline_record.sha256,
                        "design_freeze_event_id": receipt.design_freeze_event_id,
                        "experiment_id": receipt.experiment_id,
                        "receipt_id": receipt.receipt_id,
                        "output_manifest_artifact_sha256": (
                            receipt.output_manifest_artifact_sha256
                        ),
                        "result_event_id": receipt.result_event_id,
                        "stage": receipt.stage.value,
                    }
                )
            timeline_valid = (
                all(
                    receipt.run_id == run_id
                    and receipt.hypothesis_id == "hypothesis-threshold"
                    and receipt.experiment_id == "experiment-threshold-fixture"
                    and receipt.stage is ExperimentStage.EXPLORATORY
                    and receipt.design_frozen_before_execution is True
                    and receipt.frozen_before_result_visibility is True
                    for receipt in timeline_receipts
                )
                and len(
                    {
                        receipt.frozen_run_spec_artifact_sha256
                        for receipt in timeline_receipts
                    }
                )
                == 2
                and len(
                    {
                        receipt.output_manifest_artifact_sha256
                        for receipt in timeline_receipts
                    }
                )
                == 2
                and all(
                    record.sha256 in summary_record.parent_artifacts
                    for record in timeline_records
                )
            )
            result["scientific_timeline_authority"].update(
                {
                    "valid": timeline_valid,
                    "receipt_count": len(timeline_records),
                    "receipts": sorted(
                        timeline_values,
                        key=lambda value: str(value["artifact_sha256"]),
                    ),
                }
            )
            from .gates import (
                ChallengeCategory,
                ChallengeStatus,
                SoundnessVerdict,
            )
            from .paper_pipeline import _resolve_soundness

            soundness_records = tuple(
                record
                for record in records
                if record.logical_type == "scientific_soundness_assessment"
            )
            claim_graph_records = tuple(
                record
                for record in records
                if record.logical_type == "claim_evidence_graph"
            )
            if len(soundness_records) != 1 or len(claim_graph_records) != 1:
                raise OrchestrationError(
                    "vNext fixture soundness or claim-graph authority is ambiguous"
            )
            soundness_record = soundness_records[0]
            claim_graph_record = claim_graph_records[0]
            expected_central_claim_ids = ("claim-threshold-fixture",)
            soundness = _resolve_soundness(
                registry,
                soundness_record.sha256,
                claim_graph_hash=claim_graph_record.sha256,
                central_claim_ids=expected_central_claim_ids,
                ledger=None,
                run_id=None,
                confirmatory_claim_authority_hashes=(),
            )
            soundness_valid = (
                soundness.claim_graph_artifact_hash
                == claim_graph_record.sha256
                and soundness.central_claim_ids == expected_central_claim_ids
                and soundness.verdict
                is SoundnessVerdict.MORE_EXPERIMENTS_REQUIRED
                and len(soundness.challenger_reviews) == len(ChallengeCategory)
                and len(soundness.findings) == 1
                and soundness.findings[0].category
                is ChallengeCategory.EXTERNAL_VALIDITY
                and soundness.findings[0].status is ChallengeStatus.UNRESOLVED
                and soundness.findings[0].target_claim_ids
                == expected_central_claim_ids
                and soundness.findings[0].claim_graph_artifact_hash
                == claim_graph_record.sha256
                and soundness.findings[0].resolution is None
                and soundness.findings[0].resolution_receipt_hash is None
                and soundness_record.sha256 in summary_record.parent_artifacts
                and claim_graph_record.sha256 in summary_record.parent_artifacts
                and summary_value.get("scientific_soundness")
                == soundness.verdict.value
            )
            result["scientific_soundness_authority"].update(
                {
                    "valid": soundness_valid,
                    "artifact_sha256": soundness_record.sha256,
                    "claim_graph_artifact_sha256": claim_graph_record.sha256,
                    "central_claim_ids": list(soundness.central_claim_ids),
                    "verdict": soundness.verdict.value,
                }
            )
            summary_valid = (
                summary_value.get("schema_version") == VNEXT_FIXTURE_SCHEMA_VERSION
                and summary_value.get("run_id") == run_id
                and summary_value.get("fixture_notice") == VNEXT_FIXTURE_NOTICE
                and summary_value.get("system_fixture_integrity") == "PASS"
                and summary_value.get("capability_level")
                == "AUTONOMOUS_EXPLORATION_READY"
                and summary_value.get("human_e4_synthesized") is False
                and isinstance(summary_value.get("claim"), dict)
                and summary_value["claim"].get("evidence_use") == "SYSTEM_FIXTURE"
                and summary_value["claim"].get("scientific_writer_eligible") is False
                and isinstance(summary_value.get("local_mac"), dict)
                and summary_value["local_mac"].get("scientific_evidence") is False
                and isinstance(summary_value.get("paper"), dict)
                and summary_value["paper"].get("status") == "BLOCKED"
                and isinstance(summary_value.get("terminal_outcome"), dict)
                and summary_value["terminal_outcome"].get("outcome")
                == "MORE_EXPERIMENTS_REQUIRED"
                and isinstance(
                    summary_value["terminal_outcome"].get("artifact_sha256"),
                    str,
                )
                and summary_value["terminal_outcome"]["artifact_sha256"]
                in registry_records
            )
            final_event_binding_valid = (
                bool(events)
                and events[-1].metadata.get("phase") == "FINAL_VERIFICATION"
                and tuple(events[-1].artifact_hashes) == (summary_hash,)
            )
            result["summary"].update(
                {
                    "valid": summary_valid,
                    "final_event_binding_valid": final_event_binding_valid,
                }
            )

            from .research_state import (
                RESEARCH_OBJECT_TYPES,
                ReproducibilityPackage,
                ReproductionStatus,
                ResearchStateRepository,
            )

            state_records = tuple(
                record
                for record in records
                if record.logical_type.startswith("research_state.")
            )
            if not state_records or not events:
                raise OrchestrationError(
                    "vNext fixture canonical research state is absent"
                )
            first_state = safe_json_loads(
                registry.get_bytes(state_records[0].sha256)
            )
            if (
                not isinstance(first_state, dict)
                or not isinstance(first_state.get("code_version"), str)
            ):
                raise OrchestrationError(
                    "vNext fixture canonical research state code binding is absent"
                )
            code_version = first_state["code_version"]
            configuration_hash = events[0].configuration_hash
            state_events = tuple(
                event
                for event in events
                if event.metadata.get("research_state_operation")
                in {"MATERIALIZED", "SUPERSEDED"}
            )
            event_provenance_valid = bool(state_events) and all(
                event.code_version == code_version
                and event.configuration_hash == configuration_hash
                for event in state_events
            )
            repository = ResearchStateRepository(
                registry,
                ledger,
                run_id=run_id,
                code_version=code_version,
                configuration_hash=configuration_hash,
                creation_command=(
                    "scientist-one",
                    "research-os-fixture",
                    "materialize-state",
                ),
            )
            state_validation = repository.validate_state(
                expected_code_version=code_version
            )
            objects = repository.objects()
            self._verify_vnext_autonomous_implementation(
                registry=registry,
                registry_records=registry_records,
                events=events,
                summary_record=summary_record,
                summary_value=summary_value,
                research_objects=objects,
                verification=result["autonomous_implementation"],
            )
            observed_types = {item.object_type for item in objects}
            expected_types = set(RESEARCH_OBJECT_TYPES)
            reproduction_packages = tuple(
                item
                for item in objects
                if isinstance(item, ReproducibilityPackage)
            )
            non_evidentiary_reproduction_valid = (
                len(reproduction_packages) == 1
                and reproduction_packages[0].reproduction_status
                is ReproductionStatus.NOT_RUN
                and reproduction_packages[0].reproduced_at is None
                and reproduction_packages[0].metadata.get(
                    "scientific_evidence_eligible"
                )
                is False
                and reproduction_packages[0].metadata.get(
                    "scientific_reproduction_status"
                )
                == "NOT_RUN"
                and reproduction_packages[0].metadata.get(
                    "system_reproduction_passed"
                )
                is True
            )
            state_summary = summary_value.get("canonical_research_state")
            state_summary_binding_valid = (
                isinstance(state_summary, dict)
                and state_summary.get("status") == "PASS"
                and state_summary.get("object_count")
                == state_validation.object_count
                and state_summary.get("object_type_count") == len(observed_types)
            )
            final_state_records = tuple(
                record
                for record in records
                if record.logical_type
                == "canonical_research_state_final_snapshot"
            )
            final_state_valid = False
            if len(final_state_records) == 1:
                final_state = safe_json_loads(
                    registry.get_bytes(final_state_records[0].sha256)
                )
                final_state_valid = (
                    isinstance(final_state, dict)
                    and final_state.get("state_valid") is True
                    and final_state.get("canonical_object_count")
                    == state_validation.object_count
                    and set(final_state.get("object_types", ()))
                    == observed_types
                )
            canonical_state_valid = (
                state_validation.valid
                and event_provenance_valid
                and observed_types == expected_types
                and len(observed_types) == 21
                and non_evidentiary_reproduction_valid
                and state_summary_binding_valid
                and final_state_valid
            )
            result["canonical_research_state"].update(
                {
                    "valid": canonical_state_valid,
                    "object_count": state_validation.object_count,
                    "object_type_count": len(observed_types),
                    "non_evidentiary_reproduction_valid": (
                        non_evidentiary_reproduction_valid
                    ),
                    "summary_binding_valid": state_summary_binding_valid,
                }
            )

            launch_declaration_valid = result["launch_provenance"][
                "declaration_valid"
            ]
            guarded_launch_valid = result["launch_provenance"][
                "guarded_production_launch_valid"
            ]
            launch_binding_valid = launch_declaration_valid and (
                launch_mode != VNEXT_GUARDED_LAUNCH_MODE
                or guarded_launch_valid
            ) and result["restart_lineage"]["valid"]
            passed = all(
                (
                    registry_receipt_valid,
                    ledger_receipt_valid,
                    run_identity_valid,
                    artifact_references_valid,
                    closure_valid,
                    summary_valid,
                    final_event_binding_valid,
                    canonical_state_valid,
                    result["autonomous_implementation"]["valid"],
                    soundness_valid,
                    timeline_valid,
                    launch_binding_valid,
                )
            )
            if passed:
                result["status"] = "PASS"
                result["completion_authorities_valid"] = True
                result["production_completion_valid"] = (
                    launch_mode == VNEXT_GUARDED_LAUNCH_MODE
                    and guarded_launch_valid
                    and result["autonomous_implementation"][
                        "current_production_eligible"
                    ]
                )
                result["system_fixture_integrity"] = "PASS"
            else:
                issues.append("COMPLETE_AUTHORITY_BINDING_FAILED")
        except Exception as exc:
            issues.append(f"{type(exc).__name__}: {exc}")
        return result

    def _vnext_fixture_status(
        self,
        run_id: str,
        operation: Mapping[str, Any],
    ) -> dict[str, Any]:
        operation_status = str(operation["status"])
        launch_mode = str(operation["launch_mode"])
        verification = self._verify_vnext_fixture(run_id, operation)
        completed = operation_status == "COMPLETE"
        if completed and verification["status"] == "PASS":
            if verification["production_completion_valid"]:
                outcome = "SYSTEM_FIXTURE_COMPLETE"
            elif launch_mode == VNEXT_DIRECT_LAUNCH_MODE:
                outcome = "SYSTEM_FIXTURE_COMPLETE_DIRECT_TEST_API"
            else:
                outcome = "SYSTEM_FIXTURE_COMPLETE_LEGACY_LAUNCH_UNATTESTED"
        elif completed:
            outcome = "COMPLETE_BUT_UNVERIFIED"
        else:
            outcome = operation_status
        return {
            "schema_version": VNEXT_STATUS_SCHEMA_VERSION,
            "kind": "RESEARCH_OS_FIXTURE",
            "run_id": run_id,
            "status": verification["status"] if completed else "PASS",
            "operation_status": operation_status,
            "outcome": outcome,
            "recovery_policy": operation["recovery_policy"],
            "completion_verified": verification["status"] == "PASS",
            "completion_authorities_valid": verification[
                "completion_authorities_valid"
            ],
            "system_fixture_integrity": verification[
                "system_fixture_integrity"
            ],
            "error_type": operation.get("error_type"),
            "artifact_count": (
                operation.get("artifact_registry", {}).get("artifact_count")
                if completed
                else None
            ),
            "event_count": (
                operation.get("event_ledger", {}).get("event_count")
                if completed
                else None
            ),
            "resumable": False,
            "resume_supported": False,
            "reproduce_supported": False,
            "package_supported": False,
            "launch_provenance": verification["launch_provenance"],
            "restart_lineage": verification["restart_lineage"],
            "production_completion_valid": verification[
                "production_completion_valid"
            ],
            "scientific_evidence_established": False,
        }

    def _save_manifest(self, manifest: dict[str, Any]) -> None:
        manifest["updated_at"] = _utc_now()
        _atomic_json(self.root, Path("runs") / str(manifest["run_id"]) / "manifest.json", manifest)

    def _artifact(self, manifest: dict[str, Any], logical_type: str, payload: Any, *, creator: str, parents: Sequence[str] = ()) -> dict[str, Any]:
        data = _canonical_bytes(payload)
        digest = _sha256(data)
        stage = str(manifest["current_state"]).lower()
        directory = _secure_directory(self.root, Path("runs") / str(manifest["run_id"]) / "artifacts" / stage, create=True)
        filename = f"{logical_type}-{digest[:20]}.json"
        path = directory / filename
        try:
            atomic_write_bytes(
                self.root,
                path.relative_to(self.root),
                data,
                immutable=True,
            )
        except PathSecurityError as exc:
            raise OrchestrationError("immutable artifact publication failed") from exc
        registry_record = self._registry(str(manifest["run_id"])).put_bytes(
            data,
            logical_type=logical_type,
            origin="Scientist-One built-in offline workflow",
            creator_role=Role(creator),
            creation_command=self.command_context,
            parent_artifacts=parents,
            schema_version=SCHEMA_VERSION,
            mime_type="application/json",
            validation_result="PASS",
            frozen=True,
            created_at=manifest["created_at"],
        )
        record = {
            "logical_type": logical_type,
            "path": path.relative_to(self.root).as_posix(),
            "sha256": digest,
            "size": len(data),
            "schema_version": SCHEMA_VERSION,
            "mime_type": "application/json",
            "origin": "Scientist-One built-in offline workflow",
            "creator_role": creator,
            "creation_command": list(self.command_context),
            "parent_artifacts": list(parents),
            "validation_result": "PASS",
            "frozen": True,
            "registry_path": registry_record.path,
            "registry_metadata_path": registry_record.metadata_path,
            "registry_record_hash": registry_record.record_hash,
        }
        existing = manifest["artifacts"].get(logical_type)
        if existing is not None and existing != record:
            raise OrchestrationError(f"frozen logical artifact already registered: {logical_type}")
        manifest["artifacts"][logical_type] = record
        return record

    def _bind_registered_control_artifact(
        self,
        manifest: dict[str, Any],
        key: str,
        record: Any,
    ) -> dict[str, Any]:
        """Bind registrar-owned immutable authority without copying its schema."""

        if not isinstance(key, str) or not key:
            raise OrchestrationError("control artifact manifest key is invalid")
        value = {
            "logical_type": record.logical_type,
            "path": record.path,
            "sha256": record.sha256,
            "size": record.size,
            "schema_version": record.schema_version,
            "mime_type": record.mime_type,
            "origin": record.origin,
            "creator_role": record.creator_role.value,
            "creation_command": list(record.creation_command),
            "parent_artifacts": list(record.parent_artifacts),
            "validation_result": record.validation_result,
            "frozen": record.frozen,
            "registry_path": record.path,
            "registry_metadata_path": record.metadata_path,
            "registry_record_hash": record.record_hash,
        }
        existing = manifest["artifacts"].get(key)
        if existing is not None and existing != value:
            raise OrchestrationError(
                f"frozen control artifact already differs: {key}"
            )
        manifest["artifacts"][key] = value
        return value

    def _artifact_from_file(
        self,
        manifest: dict[str, Any],
        logical_type: str,
        path: Path,
        *,
        creator: str,
        mime_type: str,
        parents: Sequence[str] = (),
        max_bytes: int = 32 * 1024 * 1024,
        expected_bytes: bytes | None = None,
    ) -> dict[str, Any]:
        candidate = path if path.is_absolute() else self.root / path
        try:
            relative = candidate.relative_to(self.root)
            data = read_confined_bytes(
                self.root,
                relative,
                reject_hardlinks=True,
                max_bytes=max_bytes,
            )
        except (PathSecurityError, ValueError) as exc:
            raise OrchestrationError("generated artifact cannot be read safely") from exc
        if data is None:
            raise OrchestrationError("generated artifact disappeared")
        if expected_bytes is not None and data != expected_bytes:
            raise OrchestrationError(
                "generated artifact differs from its in-memory deterministic rendering"
            )
        digest = _sha256(data)
        directory = _secure_directory(self.root, Path("runs") / str(manifest["run_id"]) / "artifacts" / str(manifest["current_state"]).lower(), create=True)
        suffix = relative.suffix or ".bin"
        destination = directory / f"{logical_type}-{digest[:20]}{suffix}"
        try:
            atomic_write_bytes(
                self.root,
                destination.relative_to(self.root),
                data,
                immutable=True,
            )
        except PathSecurityError as exc:
            raise OrchestrationError("immutable file artifact publication failed") from exc
        registry_record = self._registry(str(manifest["run_id"])).put_bytes(
            data,
            logical_type=logical_type,
            origin="generated from machine-readable verified artifacts",
            creator_role=Role(creator),
            creation_command=self.command_context,
            parent_artifacts=parents,
            schema_version=SCHEMA_VERSION,
            mime_type=mime_type,
            validation_result="PASS",
            frozen=True,
            created_at=manifest["created_at"],
        )
        record = {
            "logical_type": logical_type,
            "path": destination.relative_to(self.root).as_posix(),
            "sha256": digest,
            "size": len(data),
            "schema_version": SCHEMA_VERSION,
            "mime_type": mime_type,
            "origin": "generated from machine-readable verified artifacts",
            "creator_role": creator,
            "creation_command": list(self.command_context),
            "parent_artifacts": list(parents),
            "validation_result": "PASS",
            "frozen": True,
            "registry_path": registry_record.path,
            "registry_metadata_path": registry_record.metadata_path,
            "registry_record_hash": registry_record.record_hash,
        }
        existing = manifest["artifacts"].get(logical_type)
        if existing is not None and existing != record:
            raise OrchestrationError(f"frozen logical artifact already registered: {logical_type}")
        manifest["artifacts"][logical_type] = record
        return record

    def _evaluate(self, manifest: dict[str, Any], key: str, evaluator: EvaluatorClass, role: Role, artifacts: Sequence[str], checks: Sequence[RCheck] = (), *, producer: Role | None = None) -> dict[str, Any]:
        hashes = tuple(manifest["artifacts"][item]["sha256"] for item in artifacts)
        reason = f"typed {key} contract passed"
        bundle = make_role_bundle(role, str(manifest["run_id"]), hashes, {"gate": key, "read_only": True}, producer_role=producer)
        evaluation = Evaluation(
            evaluator,
            role,
            Decision.PASS,
            hashes,
            reason,
            tuple(checks),
            False,
            producer,
            str(manifest["run_id"]),
            key,
            bundle.sha256,
            False,
        )
        record = legacy_evaluation_receipt(evaluation)
        manifest["evaluator_decisions"][key] = record
        return record

    def _append_event(
        self,
        manifest: dict[str, Any],
        before: str,
        after: str,
        reason: str,
        artifact_types: Sequence[str],
        evaluator_keys: Sequence[str],
        *,
        event_type: str = "TRANSITION",
        actor_role: Role = Role.ORCHESTRATOR,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        # INITIALIZED is represented as a CALIBRATE checkpoint event because
        # the typed ledger intentionally has no pseudo-state outside the state
        # machine. All later records are real typed edges.
        typed_before = "CALIBRATE" if before == "INITIALIZED" else before
        ledger = EventLedger(
            self.root, Path("runs") / str(manifest["run_id"]) / "events.jsonl"
        )
        artifact_records = [manifest["artifacts"][name] for name in artifact_types]
        stored_evaluations = [manifest["evaluator_decisions"][key] for key in evaluator_keys]
        event_metadata = {
            "schema_version": SCHEMA_VERSION,
            "initialization": before == "INITIALIZED",
            "evaluator_keys": list(evaluator_keys),
            "artifact_types": list(artifact_types),
            "artifact_record_hashes": [
                record["registry_record_hash"] for record in artifact_records
            ],
            "artifact_descriptors": [
                {
                    "logical_type": record["logical_type"],
                    "sha256": record["sha256"],
                    "registry_record_hash": record["registry_record_hash"],
                    "parent_artifacts": list(record.get("parent_artifacts", ())),
                    "parent_record_hashes": [
                        self._registry(str(manifest["run_id"]))
                        .get_metadata(parent)
                        .record_hash
                        for parent in record.get("parent_artifacts", ())
                    ],
                }
                for record in artifact_records
            ],
        }
        resource_positions = [
            index
            for index, name in enumerate(artifact_types)
            if name.startswith("resource_runtime_")
        ]
        if len(resource_positions) > 1:
            raise OrchestrationError("one event cannot bind multiple resource checkpoints")
        if resource_positions:
            authorities = self._resource_authority_records(
                str(manifest["run_id"])
            )
            if not authorities:
                raise OrchestrationError(
                    "resource checkpoint lacks an external authority record"
                )
            descriptor = self._resource_authority_descriptors(authorities)[-1]
            resource_record = artifact_records[resource_positions[0]]
            if (
                descriptor["logical_type"] != resource_record["logical_type"]
                or descriptor["state_sha256"] != resource_record["sha256"]
            ):
                raise OrchestrationError(
                    "resource checkpoint differs from the external authority head"
                )
            event_metadata["resource_authority_checkpoint"] = descriptor
        if (
            event_type in {"TRANSITION", "SECURITY_STOP"}
            and typed_before != after
            and manifest.get("typed_transition_receipts")
        ):
            event_metadata["transition_receipt"] = dict(
                manifest["typed_transition_receipts"][-1]
            )
        if metadata:
            overlap = set(event_metadata).intersection(metadata)
            if overlap:
                raise OrchestrationError(
                    "event metadata cannot replace authoritative bindings: "
                    + ", ".join(sorted(overlap))
                )
            event_metadata.update(metadata)
        event = ledger.record(
            run_id=str(manifest["run_id"]),
            event_id=f"event-{int(manifest['event_count']) + 1:04d}",
            timestamp=_utc_now(),
            actor_role=actor_role,
            state_before=typed_before,
            requested_state_after=after,
            artifact_hashes=(record["sha256"] for record in artifact_records),
            code_version=str(manifest["code_fingerprint"]),
            configuration_hash=str(manifest["configuration_sha256"]),
            dataset_identifiers=manifest["fixture_identifiers"],
            random_seeds=manifest["random_seeds"],
            evaluator_outputs=stored_evaluations,
            reason=reason,
            event_type="CHECKPOINT" if before == "INITIALIZED" else event_type,
            metadata=event_metadata,
        )
        manifest["event_count"] = int(manifest["event_count"]) + 1
        manifest["ledger_head_hash"] = event.event_hash
        return str(event.event_id)

    def _checkpoint(self, manifest: dict[str, Any]) -> None:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "run_id": manifest["run_id"],
            "state": manifest["current_state"],
            "terminal_state": manifest.get("terminal_state"),
            "event_count": manifest["event_count"],
            "ledger_head_hash": manifest.get("ledger_head_hash"),
            "artifact_hashes": {key: value["sha256"] for key, value in sorted(manifest["artifacts"].items())},
            "artifact_record_hashes": {
                key: value["registry_record_hash"]
                for key, value in sorted(manifest["artifacts"].items())
            },
            "resource_runtime_artifact": manifest.get("resource_runtime_artifact"),
            "resumable": (
                manifest.get("terminal_state") is None
                and manifest.get("resource_runtime_artifact") not in {
                    RESOURCE_RUNTIME_ADMISSION_REFUSAL, RESOURCE_RUNTIME_PILOT_FAILURE,
                }
            ),
        }
        _atomic_json(self.root, Path("runs") / str(manifest["run_id"]) / "checkpoint.json", payload)
        if manifest.get("ledger_head_hash") and manifest.get("event_count"):
            RecoveryManager(self.root).create_checkpoint(
                {
                    "run_id": manifest["run_id"],
                    "event_id": f"event-{int(manifest['event_count']):04d}",
                    "ledger_head_hash": manifest["ledger_head_hash"],
                    "state": manifest["current_state"],
                    "artifact_hashes": {
                        key: value["sha256"]
                        for key, value in sorted(manifest["artifacts"].items())
                    },
                    "artifact_record_hashes": {
                        key: value["registry_record_hash"]
                        for key, value in sorted(manifest["artifacts"].items())
                    },
                    "resource_runtime_artifact": manifest.get(
                        "resource_runtime_artifact"
                    ),
                },
                checkpoint_dir=Path(".scientist-one-build/checkpoints") / str(manifest["run_id"]),
            )
        self._save_manifest(manifest)

    def _assert_no_newer_external_checkpoint(
        self, manifest: Mapping[str, Any]
    ) -> None:
        """Reject a run projection older than any immutable external checkpoint."""

        run_id = manifest.get("run_id")
        if not isinstance(run_id, str) or not RUN_ID_PATTERN.fullmatch(run_id):
            raise OrchestrationError(
                "external checkpoint authority requires a validated run ID"
            )
        relative = Path(".scientist-one-build/checkpoints") / run_id
        try:
            directory_fd = open_confined_directory_fd(
                self.root, relative, create=False
            )
        except PathSecurityError as exc:
            raise OrchestrationError(
                "external checkpoint authority is unavailable or unsafe"
            ) from exc
        newest_count = 0
        newest_head: str | None = None
        try:
            with os.scandir(directory_fd) as iterator:
                count = 0
                for entry in iterator:
                    count += 1
                    if count > 256 or not re.fullmatch(
                        r"event-[0-9]{4}-[0-9a-f]{12}\.json", entry.name
                    ):
                        raise OrchestrationError(
                            "external checkpoint authority is malformed or oversized"
                        )
                    data = read_confined_bytes(
                        self.root,
                        relative / entry.name,
                        reject_hardlinks=True,
                        max_bytes=8 * 1024 * 1024,
                    )
                    value = safe_json_loads(data) if data is not None else None
                    if not isinstance(value, Mapping) or set(value) != {
                        "schema_version", "checkpoint_id", "run_id", "event_id",
                        "ledger_head_hash", "state", "artifact_hashes",
                        "artifact_record_hashes", "resource_runtime_artifact",
                        "created_at", "checkpoint_hash",
                    }:
                        raise OrchestrationError(
                            "external checkpoint authority has an invalid schema"
                        )
                    event_id = value.get("event_id")
                    checkpoint_hash = value.get("checkpoint_hash")
                    canonical = {
                        key: child
                        for key, child in value.items()
                        if key != "checkpoint_hash"
                    }
                    if (
                        value.get("schema_version") != SCHEMA_VERSION
                        or value.get("run_id") != run_id
                        or not isinstance(event_id, str)
                        or re.fullmatch(r"event-[0-9]{4}", event_id) is None
                        or not isinstance(checkpoint_hash, str)
                        or checkpoint_hash != _sha256(canonical_json_bytes(canonical))
                        or value.get("checkpoint_id")
                        != f"{event_id}-{str(value.get('ledger_head_hash'))[:12]}"
                    ):
                        raise OrchestrationError(
                            "external checkpoint authority binding is invalid"
                        )
                    event_count = int(event_id.removeprefix("event-"))
                    if event_count > newest_count:
                        newest_count = event_count
                        newest_head = str(value.get("ledger_head_hash"))
        finally:
            os.close(directory_fd)
        manifest_count = manifest.get("event_count")
        manifest_head = manifest.get("ledger_head_hash")
        if (
            isinstance(manifest_count, bool)
            or not isinstance(manifest_count, int)
            or newest_count > manifest_count
            or (newest_count == manifest_count and newest_head != manifest_head)
        ):
            raise OrchestrationError(
                "run projection is older than its external checkpoint authority"
            )

    def _resource_controller(
        self,
        manifest: Mapping[str, Any],
        *,
        authority_records_override: Sequence[Mapping[str, Any]] | None = None,
        ledger_events_override: Sequence[Any] | None = None,
    ) -> ResourceController:
        if isinstance(manifest.get("resource_runtime_state"), Mapping):
            if self._pilot_operation_disposition(manifest) is not None:
                raise OrchestrationError("pilot operation is durably blocked or unresolved")
            if self._resource_admission_refusal(manifest) is not None:
                raise _ResourceAdmissionBlocked("resource admission is durably blocked")
        config = ResourceConfig.from_json(
            "configs/resource_limits.json", project_root=self.root
        )
        state = manifest.get("resource_runtime_state")
        authority_records = tuple(
            authority_records_override
            if authority_records_override is not None
            else self._resource_authority_records(str(manifest["run_id"]))
        )
        if isinstance(state, Mapping):
            artifact_name = manifest.get("resource_runtime_artifact")
            if not isinstance(artifact_name, str):
                raise OrchestrationError("resource runtime state lacks an immutable artifact binding")
            record = manifest.get("artifacts", {}).get(artifact_name)
            if not isinstance(record, Mapping):
                raise OrchestrationError("resource runtime artifact is absent from the manifest")
            try:
                registry = self._registry(str(manifest["run_id"]))
                stored = registry.get_metadata(str(record["sha256"]))
                payload = safe_json_loads(registry.get_bytes(stored.sha256))
            except Exception as exc:
                raise OrchestrationError("resource runtime artifact is absent or corrupt") from exc
            if not isinstance(payload, dict):
                raise OrchestrationError("resource runtime artifact is not an object")
            ledger_result = None
            ledger_events = tuple(ledger_events_override or ())
            if ledger_events_override is None:
                ledger_result = EventLedger(
                    self.root,
                    Path("runs") / str(manifest["run_id"]) / "events.jsonl",
                ).validate()
                if not ledger_result.valid or not ledger_result.events:
                    raise OrchestrationError(
                        "resource runtime state has no valid ledger binding"
                    )
                ledger_events = ledger_result.events
            elif not ledger_events:
                raise OrchestrationError(
                    "resource runtime state has no valid ledger binding"
                )
            self._validate_resource_authority_ledger(
                authority_records, ledger_events
            )
            authoritative_hash: str | None = None
            authoritative_name: str | None = None
            for event in reversed(ledger_events):
                artifact_types = event.metadata.get("artifact_types", [])
                if not isinstance(artifact_types, (list, tuple)):
                    continue
                for index in range(len(artifact_types) - 1, -1, -1):
                    candidate = artifact_types[index]
                    if isinstance(candidate, str) and candidate.startswith("resource_runtime_"):
                        if index >= len(event.artifact_hashes):
                            raise OrchestrationError("resource checkpoint artifact binding is malformed")
                        authoritative_name = candidate
                        authoritative_hash = event.artifact_hashes[index]
                        break
                if authoritative_hash is not None:
                    break
            authoritative_state: Mapping[str, Any] | None = None
            if authority_records:
                latest_authority_state = authority_records[-1].get("state")
                if (
                    authority_records[-1].get("logical_type")
                    == RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
                    and isinstance(latest_authority_state, Mapping)
                ):
                    candidate = latest_authority_state.get("runtime_state")
                    if isinstance(candidate, Mapping):
                        authoritative_state = candidate
                elif isinstance(latest_authority_state, Mapping):
                    authoritative_state = latest_authority_state
            expected_payload: Mapping[str, Any] = (
                authority_records[-1]["state"]
                if authority_records
                and authority_records[-1].get("logical_type")
                == RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
                else dict(state)
            )
            if (
                not authority_records
                or authority_records[-1].get("logical_type") != artifact_name
                or authoritative_state != dict(state)
                or authority_records[-1].get("state_sha256")
                != record.get("sha256")
                or stored.logical_type != artifact_name
                or stored.record_hash != record.get("registry_record_hash")
                or payload != expected_payload
                or authoritative_name != artifact_name
                or authoritative_hash != record.get("sha256")
            ):
                raise OrchestrationError(
                    "resource state differs from the latest ledger-bound frozen checkpoint"
                )
            return ResourceController.from_runtime_state(config, self.root, state)
        if authority_records:
            raise OrchestrationError(
                "resource authority exists without a matching run-local state"
            )
        return ResourceController(
            config,
            self.root,
            run_id=str(manifest["run_id"]),
            validity_budget_units=10,
        )

    def _wall_budget_observation_payload(
        self,
        manifest: Mapping[str, Any],
        *,
        resource_config: ResourceConfig,
        runtime_state: ResourceRuntimeState,
    ) -> dict[str, Any]:
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, Mapping):
            raise OrchestrationError("run artifact projection is malformed")
        inventory = artifacts.get("frozen_configuration_inventory")
        prior_name = manifest.get("resource_runtime_artifact")
        prior = artifacts.get(prior_name) if isinstance(prior_name, str) else None
        if not isinstance(inventory, Mapping) or not isinstance(prior, Mapping):
            raise OrchestrationError(
                "wall-budget observation lacks frozen resource roots"
            )
        inventory_sha = inventory.get("sha256")
        inventory_record_hash = inventory.get("registry_record_hash")
        prior_sha = prior.get("sha256")
        for value in (inventory_sha, inventory_record_hash, prior_sha):
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise OrchestrationError(
                    "wall-budget observation resource root is malformed"
                )
        return {
            "schema_version": RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_SCHEMA,
            "kind": "RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION",
            "run_id": str(manifest["run_id"]),
            "frozen_configuration_inventory_artifact_sha256": inventory_sha,
            "frozen_configuration_inventory_record_hash": inventory_record_hash,
            "resource_config": resource_config.to_dict(),
            "resource_config_sha256": resource_config_sha256(resource_config),
            "runtime_state": runtime_state.to_dict(),
            "prior_resource_runtime_artifact_sha256": prior_sha,
            "authority_scope": "OPERATIONAL_TIME_OBSERVATION",
            "scientific_evidence": False,
        }

    def _load_frozen_resource_config(
        self,
        manifest: Mapping[str, Any],
    ) -> ResourceConfig:
        artifacts = manifest.get("artifacts")
        inventory_binding = (
            artifacts.get("frozen_configuration_inventory")
            if isinstance(artifacts, Mapping)
            else None
        )
        if not isinstance(inventory_binding, Mapping):
            raise OrchestrationError("frozen configuration inventory is absent")
        registry = self._registry(str(manifest["run_id"]))
        try:
            record = registry.get_metadata(str(inventory_binding["sha256"]))
            value = safe_json_loads(registry.get_bytes(record.sha256))
        except Exception as exc:
            raise OrchestrationError(
                "frozen configuration inventory cannot be reopened"
            ) from exc
        if (
            record.record_hash != inventory_binding.get("registry_record_hash")
            or record.logical_type != "frozen_configuration_inventory"
            or record.creator_role is not Role.ORCHESTRATOR
            or record.validation_result != "PASS"
            or not record.frozen
            or not isinstance(value, Mapping)
            or value.get("kind") != "FROZEN_CONFIGURATION_INVENTORY"
            or not isinstance(value.get("entries"), list)
        ):
            raise OrchestrationError("frozen configuration inventory is substituted")
        matches = [
            item
            for item in value["entries"]
            if isinstance(item, Mapping)
            and item.get("path") == "configs/resource_limits.json"
        ]
        if len(matches) != 1:
            raise OrchestrationError(
                "frozen configuration inventory lacks one resource policy"
            )
        try:
            raw = read_confined_bytes(
                self.root,
                "configs/resource_limits.json",
                reject_hardlinks=True,
                max_bytes=1024 * 1024,
            )
            raw_value = safe_json_loads(raw) if raw is not None else None
        except Exception as exc:
            raise OrchestrationError("resource configuration cannot be reopened") from exc
        entry = matches[0]
        if (
            raw is None
            or entry.get("sha256") != _sha256(raw)
            or entry.get("size") != len(raw)
            or not isinstance(raw_value, Mapping)
        ):
            raise OrchestrationError(
                "resource configuration differs from its frozen inventory"
            )
        try:
            return ResourceConfig.from_mapping(raw_value)
        except Exception as exc:
            raise OrchestrationError("frozen resource configuration is invalid") from exc

    @_project_command
    def observe_run_wall_budget(
        self,
        run_id: str,
    ) -> ResourceRuntimeWallBudgetObservation:
        """Commit one real-clock observation only after the run budget expires."""

        if not RUN_ID_PATTERN.fullmatch(run_id):
            raise OrchestrationError("wall-budget observation run ID is invalid")
        manifest = self.load_manifest(run_id)
        if manifest.get("run_id") != run_id:
            raise OrchestrationError("wall-budget observation names another run")
        registry = self._registry(run_id)
        ledger = EventLedger(
            self.root, Path("runs") / run_id / "events.jsonl"
        )
        records = self._resource_authority_records(run_id)
        observation_positions = tuple(
            index
            for index, item in enumerate(records)
            if item.get("logical_type")
            == RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
        )
        if observation_positions and observation_positions != (len(records) - 1,):
            raise OrchestrationError("wall-budget observation slot is ambiguous")

        if observation_positions:
            payload = dict(records[-1]["state"])
            prior_records = records[:-1]
        else:
            config = self._load_frozen_resource_config(manifest)
            controller = self._resource_controller(manifest)
            if controller.config_sha256 != resource_config_sha256(config):
                raise OrchestrationError(
                    "resource controller differs from frozen configuration"
                )
            runtime_state = controller.observe_wall_time()
            if (
                runtime_state.wall_elapsed_seconds
                < config.maximum_wall_clock_seconds
            ):
                raise OrchestrationError("run wall budget is not exhausted")
            prior_state = _validate_monotonic_resource_states(records)[-1]
            if runtime_state.wall_elapsed_seconds <= prior_state.wall_elapsed_seconds:
                raise OrchestrationError(
                    "wall-budget observation did not advance resource time"
                )
            payload = self._wall_budget_observation_payload(
                manifest,
                resource_config=config,
                runtime_state=runtime_state,
            )
            prior_records = records

        try:
            payload_config = ResourceConfig.from_mapping(payload["resource_config"])
            payload_state = ResourceRuntimeState.from_mapping(payload["runtime_state"])
        except Exception as exc:
            raise OrchestrationError("wall-budget observation payload is invalid") from exc
        if (
            payload.get("run_id") != run_id
            or payload.get("kind") != "RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION"
            or payload.get("authority_scope") != "OPERATIONAL_TIME_OBSERVATION"
            or payload.get("scientific_evidence") is not False
            or payload.get("resource_config_sha256")
            != resource_config_sha256(payload_config)
            or payload_state.config_sha256
            != resource_config_sha256(payload_config)
            or payload_state.wall_elapsed_seconds
            < payload_config.maximum_wall_clock_seconds
        ):
            raise OrchestrationError("wall-budget observation claim is invalid")

        data = _canonical_bytes(payload)
        if len(data) > min(MAX_ARTIFACT_OBJECT_BYTES, 1024 * 1024):
            raise OrchestrationError("wall-budget observation exceeds its byte bound")
        parents = (
            str(payload["prior_resource_runtime_artifact_sha256"]),
            str(payload["frozen_configuration_inventory_artifact_sha256"]),
        )
        if (
            len(set(parents)) != 2
            or not prior_records
            or parents[0] != prior_records[-1].get("state_sha256")
        ):
            raise OrchestrationError("wall-budget observation parents are ambiguous")

        # Materialize both lock paths before nesting them.  The enclosing
        # command guard already holds the project resource lock.
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
                if not locked_ledger.valid or any(
                    event.run_id != run_id for event in locked_ledger.events
                ):
                    raise OrchestrationError("wall-budget observation ledger is invalid")
                if not locked_ledger.events:
                    raise OrchestrationError(
                        "wall-budget observation requires an initialized ledger"
                    )

                existing_events = tuple(
                    (index, event)
                    for index, event in enumerate(locked_ledger.events)
                    if event.metadata.get("resource_wall_budget_observation")
                    is not None
                )
                if not existing_events and (
                    not isinstance(
                        locked_ledger.events[-1].requested_state_after,
                        MacroState,
                    )
                    or any(
                        isinstance(candidate.state_before, TerminalState)
                        or isinstance(
                            candidate.requested_state_after,
                            TerminalState,
                        )
                        for candidate in locked_ledger.events
                    )
                ):
                    raise OrchestrationError(
                        "wall-budget observation cannot follow a terminal run state"
                    )
                if observation_positions:
                    if existing_events:
                        self._validate_resource_authority_ledger(
                            records, locked_ledger.events
                        )
                    else:
                        self._validate_resource_authority_ledger(
                            prior_records, locked_ledger.events
                        )
                else:
                    if existing_events:
                        raise OrchestrationError(
                            "wall-budget observation event lacks external authority"
                        )
                    self._validate_resource_authority_ledger(
                        prior_records, locked_ledger.events
                    )
                checkpoint_records = (
                    records
                    if observation_positions and existing_events
                    else prior_records
                )
                _require_exact_resource_checkpoint_closure(
                    registry,
                    checkpoint_records,
                    locked_ledger.events,
                    registry_guard=registry_guard,
                )

                projected_manifest = safe_json_loads(_canonical_bytes(manifest))
                if not isinstance(projected_manifest, dict):
                    raise OrchestrationError("run manifest is malformed")
                projected_artifacts = projected_manifest.get("artifacts")
                if not isinstance(projected_artifacts, Mapping):
                    raise OrchestrationError("run artifact projection is malformed")

                initial_event = locked_ledger.events[0]
                initial_inventory_binding = _resource_event_artifact_binding(
                    initial_event,
                    "frozen_configuration_inventory",
                )
                projected_inventory = projected_artifacts.get(
                    "frozen_configuration_inventory"
                )
                if (
                    initial_event.metadata.get("initialization") is not True
                    or initial_inventory_binding is None
                    or not isinstance(projected_inventory, Mapping)
                ):
                    raise OrchestrationError(
                        "wall-budget observation lacks its initialization inventory"
                    )
                inventory_position, inventory_record_hash = (
                    initial_inventory_binding
                )
                initial_inventory_sha256 = initial_event.artifact_hashes[
                    inventory_position
                ]
                try:
                    initial_inventory_record = registry._get_metadata_locked(
                        registry_guard,
                        initial_inventory_sha256,
                    )
                except Exception as exc:
                    raise OrchestrationError(
                        "wall-budget initialization inventory cannot be reopened"
                    ) from exc
                if (
                    projected_inventory.get("sha256")
                    != initial_inventory_sha256
                    or projected_inventory.get("registry_record_hash")
                    != inventory_record_hash
                    or parents[1] != initial_inventory_sha256
                    or payload.get(
                        "frozen_configuration_inventory_artifact_sha256"
                    )
                    != initial_inventory_sha256
                    or payload.get(
                        "frozen_configuration_inventory_record_hash"
                    )
                    != inventory_record_hash
                    or initial_inventory_record.record_hash
                    != inventory_record_hash
                    or any(
                        candidate.event_type == "CORRECTION"
                        and candidate.supersedes_event_id
                        == initial_event.event_id
                        for candidate in locked_ledger.events[1:]
                    )
                ):
                    raise OrchestrationError(
                        "wall-budget initialization inventory binding is substituted"
                    )
                projected_fixture_ids = projected_manifest.get(
                    "fixture_identifiers"
                )
                projected_random_seeds = projected_manifest.get("random_seeds")
                if (
                    projected_manifest.get("code_fingerprint")
                    != initial_event.code_version
                    or projected_manifest.get("configuration_sha256")
                    != initial_event.configuration_hash
                    or not isinstance(projected_fixture_ids, (list, tuple))
                    or tuple(projected_fixture_ids)
                    != initial_event.dataset_identifiers
                    or not isinstance(projected_random_seeds, (list, tuple))
                    or tuple(projected_random_seeds)
                    != initial_event.random_seeds
                    or (
                        not existing_events
                        and projected_manifest.get("current_state")
                        != locked_ledger.events[-1].requested_state_after.value
                    )
                ):
                    raise OrchestrationError(
                        "wall-budget observation manifest provenance is stale or substituted"
                    )

                digest = _sha256(data)
                existing_record = next(
                    (
                        item
                        for item in locked_registry.records
                        if item.sha256 == digest
                    ),
                    None,
                )
                if existing_record is not None and not registry._semantic_match(
                    existing_record,
                    logical_type=(
                        RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
                    ),
                    schema_version="1.0",
                    mime_type="application/json",
                    origin=_RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_ORIGIN,
                    creator_role=Role.ORCHESTRATOR,
                    creation_command=(
                        _RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_COMMAND
                    ),
                    parents=parents,
                    validation_result="PASS",
                    frozen=True,
                ):
                    raise OrchestrationError(
                        "wall-budget observation registry slot has conflicting metadata"
                    )
                records_needed = 0 if existing_record is not None else 1
                events_needed = 0 if existing_events else 1
                if len(records) + (0 if observation_positions else 1) > 16:
                    raise OrchestrationError("resource authority history is full")
                if locked_registry.count + records_needed > MAX_REGISTRY_RECORDS:
                    raise OrchestrationError("resource registry capacity is insufficient")
                if locked_ledger.event_count + events_needed > MAX_LEDGER_EVENTS:
                    raise OrchestrationError("resource ledger capacity is insufficient")
                if (
                    events_needed
                    and locked_ledger.valid_prefix_bytes + 8 * 1024 * 1024
                    > MAX_LEDGER_BYTES
                ):
                    raise OrchestrationError(
                        "resource ledger byte capacity is insufficient"
                    )

                projected_observation = projected_artifacts.get(
                    RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
                )
                projected_observation_is_exact = False
                if not observation_positions and projected_observation is not None:
                    raise OrchestrationError(
                        "wall-budget observation manifest slot is already occupied"
                    )
                if observation_positions and projected_observation is not None:
                    if existing_record is None:
                        raise OrchestrationError(
                            "wall-budget observation manifest slot lacks its registry record"
                        )
                    expected_projection = {
                        "logical_type": existing_record.logical_type,
                        "path": existing_record.path,
                        "sha256": existing_record.sha256,
                        "size": existing_record.size,
                        "schema_version": existing_record.schema_version,
                        "mime_type": existing_record.mime_type,
                        "origin": existing_record.origin,
                        "creator_role": existing_record.creator_role.value,
                        "creation_command": list(existing_record.creation_command),
                        "parent_artifacts": list(existing_record.parent_artifacts),
                        "validation_result": existing_record.validation_result,
                        "frozen": existing_record.frozen,
                        "registry_path": existing_record.path,
                        "registry_metadata_path": existing_record.metadata_path,
                        "registry_record_hash": existing_record.record_hash,
                    }
                    if projected_observation != expected_projection:
                        raise OrchestrationError(
                            "wall-budget observation manifest recovery slot is conflicting"
                        )
                    projected_observation_is_exact = True
                if observation_positions:
                    prior_runtime_state = _runtime_state_from_authority_record(
                        prior_records[-1]
                    )
                    prior_projection_is_exact = (
                        projected_manifest.get("resource_runtime_state")
                        == prior_runtime_state.to_dict()
                        and projected_manifest.get("resource_runtime_artifact")
                        == prior_records[-1]["logical_type"]
                        and projected_observation is None
                    )
                    observation_projection_is_exact = (
                        projected_manifest.get("resource_runtime_state")
                        == payload_state.to_dict()
                        and projected_manifest.get("resource_runtime_artifact")
                        == RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
                        and projected_observation_is_exact
                    )
                    if not (
                        prior_projection_is_exact
                        or observation_projection_is_exact
                    ):
                        raise OrchestrationError(
                            "wall-budget observation manifest resource head is conflicting"
                        )
                if len(_canonical_bytes(projected_manifest)) + len(data) + 16 * 1024 > 16 * 1024 * 1024:
                    raise OrchestrationError(
                        "wall-budget observation manifest capacity is insufficient"
                    )

                external = self._persist_resource_authority(
                    manifest,
                    RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE,
                    payload,
                )
                all_records = self._resource_authority_records(run_id)
                _validate_monotonic_resource_states(all_records)
                descriptor = self._resource_authority_descriptors(all_records)[-1]
                record = registry._put_bytes_locked(
                    registry_guard,
                    data,
                    logical_type=RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE,
                    origin=_RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_ORIGIN,
                    creator_role=Role.ORCHESTRATOR,
                    creation_command=_RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_COMMAND,
                    parent_artifacts=parents,
                    schema_version="1.0",
                    mime_type="application/json",
                    validation_result="PASS",
                    frozen=True,
                    created_at=None,
                )
                if record.sha256 != external["state_sha256"]:
                    raise OrchestrationError(
                        "external wall observation differs from registry bytes"
                    )
                parent_record_hashes = [
                    str(registry._get_metadata_locked(registry_guard, item).record_hash)
                    for item in parents
                ]
                binding = {
                    "schema_version": RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_SCHEMA,
                    "run_id": run_id,
                    "observation_artifact_sha256": record.sha256,
                    "observation_record_hash": str(record.record_hash),
                    "prior_resource_runtime_artifact_sha256": parents[0],
                    "frozen_configuration_inventory_artifact_sha256": parents[1],
                    "resource_config_sha256": payload["resource_config_sha256"],
                    "wall_elapsed_seconds": payload_state.wall_elapsed_seconds,
                    "maximum_wall_clock_seconds": (
                        payload_config.maximum_wall_clock_seconds
                    ),
                    "external_authority_sequence": external["sequence"],
                    "external_authority_sha256": descriptor["authority_sha256"],
                    "authority_scope": "OPERATIONAL_TIME_OBSERVATION",
                    "scientific_evidence": False,
                }
                metadata = {
                    "schema_version": SCHEMA_VERSION,
                    "initialization": False,
                    "evaluator_keys": [],
                    "artifact_types": [
                        RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
                    ],
                    "artifact_record_hashes": [str(record.record_hash)],
                    "artifact_descriptors": [
                        {
                            "logical_type": record.logical_type,
                            "sha256": record.sha256,
                            "registry_record_hash": str(record.record_hash),
                            "parent_artifacts": list(parents),
                            "parent_record_hashes": parent_record_hashes,
                        }
                    ],
                    "resource_authority_checkpoint": descriptor,
                    "resource_wall_budget_observation": binding,
                }

                def build_event(snapshot: Any) -> LedgerEvent:
                    state = (
                        snapshot.events[-1].requested_state_after
                        if snapshot.events
                        else MacroState.CALIBRATE
                    )
                    timestamp = datetime.fromtimestamp(
                        payload_state.wall_observed_at_epoch_seconds,
                        timezone.utc,
                    ).isoformat().replace("+00:00", "Z")
                    return LedgerEvent.create(
                        run_id=run_id,
                        event_id=f"event-{snapshot.event_count + 1:04d}",
                        timestamp=timestamp,
                        actor_role=Role.ORCHESTRATOR,
                        state_before=state,
                        requested_state_after=state,
                        artifact_hashes=(record.sha256,),
                        code_version=str(manifest["code_fingerprint"]),
                        configuration_hash=str(manifest["configuration_sha256"]),
                        dataset_identifiers=tuple(manifest["fixture_identifiers"]),
                        random_seeds=tuple(manifest["random_seeds"]),
                        evaluator_outputs=(),
                        reason="committed exhausted run wall budget from built-in clocks",
                        prior_event_hash=snapshot.head_hash,
                        event_type="CHECKPOINT",
                        metadata=metadata,
                    )

                if existing_events:
                    if len(existing_events) != 1:
                        raise OrchestrationError(
                            "wall-budget observation event slot is ambiguous"
                        )
                    event_index, event = existing_events[0]
                    prefix = type(locked_ledger)(
                        True,
                        locked_ledger.events[:event_index],
                        (
                            locked_ledger.events[event_index - 1].event_hash
                            if event_index
                            else None
                        ),
                        valid_prefix_bytes=0,
                    )
                    if event != build_event(prefix):
                        raise OrchestrationError(
                            "wall-budget observation event is substituted"
                        )
                    committed = locked_ledger
                else:
                    expected = build_event(locked_ledger)
                    line = canonical_json_bytes(expected.to_dict()) + b"\n"
                    if (
                        len(line) > 8 * 1024 * 1024
                        or locked_ledger.valid_prefix_bytes + len(line)
                        > MAX_LEDGER_BYTES
                    ):
                        raise OrchestrationError(
                            "wall-budget observation event exceeds ledger capacity"
                        )
                    event = ledger._append_locked(ledger_guard, build_event)
                    event_index = locked_ledger.event_count
                    committed = ledger._validate_bytes(
                        ledger._read_raw_locked(ledger_guard)
                    )
                if not committed.valid:
                    raise OrchestrationError(
                        "wall-budget observation ledger append did not verify"
                    )
            finally:
                ledger._unlock(ledger_guard)
        finally:
            registry._unlock_mutation(registry_guard)

        self._bind_registered_control_artifact(
            manifest,
            RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE,
            record,
        )
        manifest["resource_runtime_state"] = payload_state.to_dict()
        manifest["resource_runtime_artifact"] = (
            RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
        )
        manifest["event_count"] = committed.event_count
        manifest["ledger_head_hash"] = committed.head_hash
        if len(_canonical_bytes(manifest)) > 16 * 1024 * 1024:
            raise OrchestrationError("wall-budget observation manifest is too large")
        self._checkpoint(manifest)
        return _require_resource_wall_observation_locked(
            registry,
            ledger,
            observation_artifact_sha256=record.sha256,
            expected_run_id=run_id,
            project_lock_held=True,
        )

    def _pilot_census(self, run_id):
        """Bounded read-only census of this run's three publication namespaces."""
        roots = {
            Path("runs") / run_id / "artifacts": "MIRROR",
            Path("runs") / run_id / "registry/objects": "OBJECT",
            Path("runs") / run_id / "registry/metadata": "METADATA",
        }
        names, directories = {}, {}
        pending = list(roots.items())
        total = 0
        while pending:
            relative, kind = pending.pop()
            fd = open_confined_directory_fd(self.root, relative, create=False)
            try:
                directory_stat = os.fstat(fd)
                directories[relative.as_posix()] = (directory_stat.st_dev, directory_stat.st_ino)
                with os.scandir(fd) as entries:
                    for entry in entries:
                        if len(names) + len(directories) + len(pending) >= MAX_INVENTORY_ENTRIES:
                            raise OrchestrationError("pilot publication census exceeds entry bound")
                        path = relative / entry.name
                        observed = entry.stat(follow_symlinks=False)
                        if stat.S_ISDIR(observed.st_mode):
                            pending.append((path, kind))
                        elif stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1:
                            if observed.st_size > MAX_ARTIFACT_OBJECT_BYTES:
                                raise OrchestrationError("pilot publication census object is too large")
                            total += observed.st_size
                            if total > MAX_INVENTORY_TOTAL_BYTES:
                                raise OrchestrationError("pilot publication census exceeds byte bound")
                            names[path.as_posix()] = (kind, observed)
                        else:
                            raise OrchestrationError("pilot publication census has unsupported file kind")
            finally:
                os.close(fd)
        # Enumeration and aggregate bounds precede retaining any contents.
        files = {}
        for path, (kind, observed) in sorted(names.items()):
            raw = read_confined_bytes(self.root, path, reject_hardlinks=True,
                                     max_bytes=MAX_ARTIFACT_OBJECT_BYTES)
            current = os.stat(self.root / path, follow_symlinks=False)
            def identity(s):
                return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns,
                        s.st_ctime_ns, s.st_mode, s.st_nlink)
            if raw is None or identity(observed) != identity(current) or len(raw) != observed.st_size:
                raise OrchestrationError("pilot publication census changed while reading")
            files[path] = {"raw": raw, "identity": identity(current), "kind": kind}
        return {"files": files, "directories": directories}

    @staticmethod
    def _pilot_inventory(census):
        return [{"path": path, "sha256": _sha256(item["raw"]),
                 "size": len(item["raw"]), "kind": item["kind"]}
                for path, item in sorted(census["files"].items())]

    @staticmethod
    def _pilot_binding(record, run_id, stage="candidate"):
        return {
            "logical_type": record.logical_type,
            "path": (Path("runs") / run_id / "artifacts" / stage
                     / f"{record.logical_type}-{record.sha256[:20]}.json").as_posix(),
            "sha256": record.sha256, "size": record.size,
            "schema_version": record.schema_version, "mime_type": record.mime_type,
            "origin": record.origin, "creator_role": record.creator_role.value,
            "creation_command": list(record.creation_command),
            "parent_artifacts": list(record.parent_artifacts),
            "validation_result": record.validation_result, "frozen": record.frozen,
            "registry_path": record.path, "registry_metadata_path": record.metadata_path,
            "registry_record_hash": record.record_hash,
        }

    def _pilot_record(self, manifest, name, payload, creator, parents, command):
        registry = self._registry(manifest["run_id"])
        raw = _canonical_bytes(payload)
        digest = _sha256(raw)
        path = registry._object_relative(digest).as_posix()
        return ArtifactRecord(
            sha256=digest, path=path, relative_path=path,
            metadata_path=registry._metadata_relative(digest).as_posix(),
            logical_type=name, schema_version=SCHEMA_VERSION,
            mime_type="application/json", size=len(raw),
            origin=_BUILTIN_OFFLINE_ARTIFACT_ORIGIN, creator_role=Role(creator),
            creation_command=tuple(command), parent_artifacts=tuple(parents),
            validation_result="PASS", frozen=True, created_at=manifest["created_at"],
        )

    def _pilot_checkpoint(self, manifest, events, *, failure=False, local=True, terminal=None):
        """Read an actual checkpoint; never synthesize a charge checkpoint."""
        event = events[-1]
        common = {
            "schema_version": SCHEMA_VERSION, "run_id": manifest["run_id"],
            "state": event.requested_state_after.value,
            "artifact_hashes": {k: v["sha256"] for k, v in sorted(manifest["artifacts"].items())},
            "artifact_record_hashes": {k: v["registry_record_hash"] for k, v in sorted(manifest["artifacts"].items())},
            "resource_runtime_artifact": manifest["resource_runtime_artifact"],
            "ledger_head_hash": event.event_hash,
        }
        expected_local = {**common, "terminal_state": terminal, "event_count": len(events),
                          "resumable": not failure and terminal is None}
        if local and _canonical_bytes(_read_json(self.root / "runs" / manifest["run_id"] / "checkpoint.json")) != _canonical_bytes(expected_local):
            raise OrchestrationError("pilot checkpoint local projection differs")
        checkpoint_id = f"{event.event_id}-{event.event_hash[:12]}"
        relative = Path(".scientist-one-build/checkpoints") / manifest["run_id"] / (checkpoint_id + ".json")
        value = _read_json(self.root / relative)
        if (set(value) != set(common) | {"event_id", "checkpoint_id", "created_at", "checkpoint_hash"}
                or any(value.get(k) != v for k, v in common.items())
                or value["event_id"] != event.event_id or value["checkpoint_id"] != checkpoint_id
                or value["checkpoint_hash"] != _sha256(canonical_json_bytes(
                    {k: v for k, v in value.items() if k != "checkpoint_hash"}))):
            raise OrchestrationError("pilot checkpoint external projection differs")
        paths = tuple((self.root / relative.parent).glob("*.json"))
        if len(paths) > 256 or sum(_read_json(p).get("event_id") == event.event_id for p in paths) != 1:
            raise OrchestrationError("pilot checkpoint slot is ambiguous")
        return {"local": expected_local, "external_path": relative.as_posix(), "external": value}

    def _pilot_base(self, manifest, registry, authorities, events, population, *, replay=False):
        """Validate the exact real charged base, not successful stage closure."""
        if (tuple(r["logical_type"] for r in authorities) != (
                "resource_runtime_initial", "resource_runtime_pilot_charge")
                or len(events) < 2 or manifest.get("current_state") != "CANDIDATE"
                or manifest.get("terminal_state") is not None or manifest.get("outcome") != "IN_PROGRESS"
                or manifest.get("pending_terminal") is not None):
            raise OrchestrationError("pilot charged base is not an ordinary CANDIDATE")
        direct = _require_builtin_resource_checkpoint_records(registry, authorities, events)
        self._validate_resource_authority_ledger(authorities, events)
        initial, charged = _validate_monotonic_resource_states(authorities)
        charge_metadata = thaw_json(events[-1].metadata)
        if (direct[-1][0] != len(events) - 1
                or events[-1].state_before is not MacroState.CANDIDATE
                or charge_metadata.get("artifact_types") != ["resource_runtime_pilot_charge"]
                or set(charge_metadata) != {"schema_version", "initialization", "evaluator_keys",
                    "artifact_types", "artifact_record_hashes", "artifact_descriptors", "resource_authority_checkpoint"}
                or charge_metadata.get("schema_version") != SCHEMA_VERSION
                or charge_metadata.get("initialization") is not False
                or charge_metadata.get("evaluator_keys") != []
                or initial.validity_total_units != 10 or initial.exploratory_used != 0
                or initial.confirmatory_used != 0 or charged.exploratory_used != 2
                or charged.confirmatory_used != 0
                or charged.worker_crashes != initial.worker_crashes
                or charged.progress_elapsed_seconds != initial.progress_elapsed_seconds
                or charged.checkpoint_elapsed_seconds != initial.checkpoint_elapsed_seconds
                or manifest.get("resource_runtime_state") != charged.to_dict()
                or manifest.get("resource_runtime_artifact") != "resource_runtime_pilot_charge"
                or manifest.get("event_count") != len(events)
                or manifest.get("ledger_head_hash") != events[-1].event_hash):
            raise OrchestrationError("pilot charged base accounting or checkpoint differs")
        # Active/failure paths retain live equality. Historical negative-only
        # recognition below must not reinterpret old hashes as today's policy.
        if (_source_inventory(self.root) != self._json_artifact_payload(manifest, "frozen_source_inventory")
                or _configuration_inventory(self.root) != self._json_artifact_payload(manifest, "frozen_configuration_inventory")
                or charged.config_sha256 != resource_config_sha256(self._load_frozen_resource_config(manifest))):
            raise OrchestrationError("pilot charged base source or configuration changed")
        context = self._pilot_base_projection(manifest, registry, events, population)
        previous = safe_json_loads(_canonical_bytes(manifest))
        previous["artifacts"].pop("resource_runtime_pilot_charge")
        previous["resource_runtime_artifact"] = "resource_runtime_initial"
        checkpoint = self._pilot_checkpoint(previous, events[:-1], local=not replay)
        return checkpoint, context

    def _pilot_base_projection(self, manifest, registry, events, population):
        """One exact pre-PILOT artifact/provenance join, also used by its old stop."""
        run_id = manifest["run_id"]
        first = events[0]
        source = self._json_artifact_payload(manifest, "frozen_source_inventory")
        config = self._json_artifact_payload(manifest, "frozen_configuration_inventory")
        # Each caller has already joined the canonical registered inventories
        # through _require_builtin_resource_checkpoint_records to event zero.
        if (source["aggregate_sha256"] != manifest["code_fingerprint"]
                or config["aggregate_sha256"] != manifest["configuration_sha256"]):
            raise OrchestrationError("pilot recorded source or configuration differs")
        records = {r.sha256: r for r in population}
        if len(records) != len(population) or len(records) != len(manifest["artifacts"]):
            raise OrchestrationError("pilot base contains unbound registry population")
        projections, evaluations, stages = {}, {}, {}
        for event in events:
            if (event.run_id != run_id or event.code_version != first.code_version
                    or event.configuration_hash != first.configuration_hash
                    or event.dataset_identifiers != first.dataset_identifiers
                    or event.random_seeds != first.random_seeds
                    or event.code_version != manifest["code_fingerprint"]
                    or event.configuration_hash != manifest["configuration_sha256"]
                    or tuple(manifest["fixture_identifiers"]) != event.dataset_identifiers
                    or tuple(manifest["random_seeds"]) != event.random_seeds):
                raise OrchestrationError("pilot base initialization context differs")
            md = thaw_json(event.metadata)
            names, hashes, descriptors = (md.get("artifact_types"), md.get("artifact_record_hashes"),
                                         md.get("artifact_descriptors"))
            if (not all(isinstance(v, list) for v in (names, hashes, descriptors))
                    or len(names) != len(event.artifact_hashes) or len(hashes) != len(names)
                    or len(descriptors) != len(names)):
                raise OrchestrationError("pilot base ledger artifact shape differs")
            for name, digest, record_hash, descriptor in zip(names, event.artifact_hashes, hashes, descriptors, strict=True):
                record = records.get(digest)
                if (record is None or record.logical_type != name or record.record_hash != record_hash
                        or descriptor != {"logical_type": name, "sha256": digest,
                            "registry_record_hash": record_hash,
                            "parent_artifacts": list(record.parent_artifacts),
                            "parent_record_hashes": [records[p].record_hash for p in record.parent_artifacts]}
                        or (name in projections and projections[name] != digest)):
                    raise OrchestrationError("pilot base ledger descriptor differs")
                projections[name] = digest
                stages.setdefault(name, event.state_before.value.lower())
            keys = md.get("evaluator_keys")
            if not isinstance(keys, list) or len(keys) != len(event.evaluator_outputs):
                raise OrchestrationError("pilot base evaluator projection differs")
            for key, evaluation in zip(keys, event.evaluator_outputs, strict=True):
                value = thaw_json(evaluation)
                if key in evaluations and evaluations[key] != value:
                    raise OrchestrationError("pilot base evaluator was superseded")
                evaluations[key] = value
        if (set(projections) != set(manifest["artifacts"])
                or set(projections.values()) != set(records)
                or evaluations != manifest["evaluator_decisions"]
                or any(key.startswith("E") and key.endswith(":CANDIDATE") for key in evaluations)):
            raise OrchestrationError("pilot base ledger/registry/manifest closure differs")
        for name, digest in projections.items():
            record = records[digest]
            binding = self._pilot_binding(record, run_id, stages[name])
            expected_origin, expected_mime = _BUILTIN_OFFLINE_ARTIFACT_ORIGIN, "application/json"
            if name == "research_brief":
                # The existing start(brief=...) owner registers supplied text,
                # including its original suffix, before any PILOT is possible.
                mirror = Path(manifest["artifacts"][name]["path"])
                expected_parent = Path("runs") / run_id / "artifacts" / stages[name]
                if (mirror.parent != expected_parent or not mirror.suffix
                        or mirror.stem != f"{name}-{digest[:20]}"
                        or record.creator_role is not Role.PROBLEM_INVESTIGATOR
                        or record.parent_artifacts):
                    raise OrchestrationError("pilot base research brief owner differs")
                binding["path"] = mirror.as_posix()
                expected_origin, expected_mime = "generated from machine-readable verified artifacts", "text/markdown"
            if (record.origin != expected_origin
                    or record.schema_version != SCHEMA_VERSION or record.mime_type != expected_mime
                    or record.created_at != manifest["created_at"]
                    or record.validation_result != "PASS" or record.frozen is not True
                    or not _supported_builtin_resource_command(record.creation_command, run_id=run_id)
                    or _canonical_bytes(manifest["artifacts"][name]) != _canonical_bytes(binding)
                    or read_confined_bytes(self.root, binding["path"], reject_hardlinks=True,
                                           max_bytes=MAX_ARTIFACT_OBJECT_BYTES) != registry.get_bytes(digest)):
                raise OrchestrationError("pilot base artifact projection differs")
        intent = self._json_artifact_payload(manifest, "run_intent")
        if intent != {"schema_version": SCHEMA_VERSION, "kind": "FROZEN_RUN_INTENT",
                      "mode": manifest["mode"], "synthetic_scenario": manifest["synthetic_scenario"],
                      "package_kind": manifest["package_kind"]}:
            raise OrchestrationError("pilot charged base differs from initialized run intent")
        receipts = validate_legacy_transition_prefix(tuple(e.to_dict() for e in events))
        if (tuple(r.to_dict() for r in receipts) != tuple(manifest["typed_transition_receipts"])
                or [f"{r.prior_state.value}->{r.current_state.value}" for r in receipts]
                != manifest["completed_transitions"]
                or StateController(initial_state=parse_state(manifest["current_state"]), artifact_registry=registry,
                                   prior_receipts=receipts).current_state != parse_state(manifest["current_state"])):
            raise OrchestrationError("pilot base transition authority differs")
        context = {name: {"sha256": manifest["artifacts"][name]["sha256"],
                          "record_hash": manifest["artifacts"][name]["registry_record_hash"]}
                   for name in ("frozen_source_inventory", "frozen_configuration_inventory", "workflow_benchmark")}
        context.update(code_fingerprint=manifest["code_fingerprint"], configuration_sha256=manifest["configuration_sha256"],
                       fixture_identifiers=list(first.dataset_identifiers), random_seeds=list(first.random_seeds))
        return context

    def _pilot_expected_files(self, manifest, records):
        registry = self._registry(manifest["run_id"])
        expected = {}
        for record in records:
            binding = manifest["artifacts"][record.logical_type]
            raw = registry.get_bytes(record.sha256)
            for path, data, kind in ((binding["path"], raw, "MIRROR"),
                                     (record.path, raw, "OBJECT"),
                                     (record.metadata_path, _canonical_bytes(record.to_dict()), "METADATA")):
                if path in expected:
                    raise OrchestrationError("pilot publication file population aliases")
                expected[path] = {"raw": data, "kind": kind}
        return expected

    @staticmethod
    def _pilot_directories(run_id, paths):
        roots = {f"runs/{run_id}/artifacts", (Path("runs") / run_id / "registry" / "objects").as_posix(),
                 (Path("runs") / run_id / "registry" / "metadata").as_posix()}
        result = set(roots)
        for name in paths:
            current = Path(name).parent
            while current.as_posix() not in roots:
                if current == Path("."):
                    raise OrchestrationError("pilot census path is outside publication namespaces")
                result.add(current.as_posix())
                current = current.parent
        return result

    def _pilot_control_snapshot(self, run_id):
        paths = [Path("runs") / run_id / name
                 for name in ("manifest.json", "events.jsonl", "checkpoint.json")]
        directories = {}
        for base, limit in ((".scientist-one-build/resource-authority", 16),
                            (".scientist-one-build/checkpoints", 256)):
            relative = Path(base) / run_id
            fd = open_confined_directory_fd(self.root, relative, create=False)
            try:
                metadata = os.fstat(fd)
                directories[relative.as_posix()] = (metadata.st_dev, metadata.st_ino)
                count = 0
                with os.scandir(fd) as entries:
                    for entry in entries:
                        count += 1
                        if count > limit or not entry.name.endswith(".json"):
                            raise OrchestrationError("pilot control census exceeds its exact namespace")
                        paths.append(relative / entry.name)
            finally:
                os.close(fd)
        files = {}
        total = 0
        for relative in sorted(paths):
            metadata = os.stat(self.root / relative, follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OrchestrationError("pilot control census has unsupported file kind")
            total += metadata.st_size
            if total > MAX_INVENTORY_TOTAL_BYTES:
                raise OrchestrationError("pilot control census exceeds byte bound")
            raw = read_confined_bytes(self.root, relative, reject_hardlinks=True,
                                     max_bytes=MAX_LEDGER_BYTES)
            def identity(s):
                return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns,
                        s.st_ctime_ns, s.st_mode, s.st_nlink)
            if raw is None or identity(metadata) != identity(os.stat(self.root / relative, follow_symlinks=False)):
                raise OrchestrationError("pilot control census changed while reading")
            files[relative.as_posix()] = (raw, identity(metadata))
        return {"files": files, "directories": directories}

    def _capture_pilot_base(self, manifest):
        if not self._command_guard_depth() or not getattr(self._command_guard_state, "resource_transaction_active", False):
            raise OrchestrationError("owned pilot base lacks its active command/resource boundary")
        run_id = manifest["run_id"]
        raw = read_confined_bytes(self.root, Path("runs") / run_id / "manifest.json",
                                 reject_hardlinks=True, max_bytes=16 * 1024 * 1024)
        if raw != _canonical_bytes(manifest):
            raise OrchestrationError("owned pilot base differs from committed charge projection")
        detached = safe_json_loads(raw)
        registry = self._registry(run_id)
        population = registry.verify_all(raise_on_error=True)
        ledger = EventLedger(self.root, Path("runs") / run_id / "events.jsonl").assert_valid()
        authorities = self._resource_authority_records(run_id)
        checkpoint, context = self._pilot_base(detached, registry, authorities, ledger.events, population.records)
        if tuple(registry.get_metadata(authorities[-1]["state_sha256"]).creation_command) != tuple(self.command_context):
            raise OrchestrationError("owned pilot command differs from actual charge producer")
        census = self._pilot_census(run_id)
        expected = self._pilot_expected_files(detached, population.records)
        if ({p: {"raw": v["raw"], "kind": v["kind"]} for p, v in census["files"].items()} != expected
                or set(census["directories"]) != self._pilot_directories(run_id, expected)):
            raise OrchestrationError("pilot charged base census contains unbound files or directories")
        # This retained observation is invocation-local, never a serialized
        # capability or caller-provided exception authority.
        return {"manifest_raw": raw, "manifest": detached, "population": population,
                "ledger": ledger, "authorities": authorities, "checkpoint": checkpoint,
                "context": context, "census": census, "command": tuple(self.command_context),
                "control": self._pilot_control_snapshot(run_id)}

    def _pilot_prefix(self, base, population, census, *, maximum=3):
        manifest = base["manifest"]
        baseline = {r.sha256: r for r in base["population"].records}
        observed = {r.sha256: r for r in population.records}
        if any(observed.get(key) != record for key, record in baseline.items()):
            raise OrchestrationError("pilot prefix changed the charged registry population")
        additions = {key: value for key, value in observed.items() if key not in baseline}
        expected = []
        for name, payload, creator, parents in self._pilot_publications(manifest):
            expected.append(self._pilot_record(manifest, name, payload, creator, parents, base["command"]))
        count = len(additions)
        if count > maximum or additions != {r.sha256: r for r in expected[:count]}:
            raise OrchestrationError("pilot output is not a complete supported source-derived prefix")
        projected = safe_json_loads(base["manifest_raw"])
        for record in expected[:count]:
            projected["artifacts"][record.logical_type] = self._pilot_binding(record, manifest["run_id"])
        expected_files = self._pilot_expected_files(projected, (*baseline.values(), *expected[:count]))
        actual_files = {p: {"raw": v["raw"], "kind": v["kind"]} for p, v in census["files"].items()}
        needed_dirs = self._pilot_directories(manifest["run_id"], expected_files)
        actual_dirs = set(census["directories"])
        # _artifact may create its stage directory before its first byte. No
        # other empty directory is part of this bounded publication prefix.
        optional = {(Path("runs") / manifest["run_id"] / "artifacts" / "candidate").as_posix()}
        if actual_files != expected_files or not needed_dirs <= actual_dirs <= needed_dirs | optional:
            raise OrchestrationError("pilot prefix has partial or unknown publication paths")
        for path, item in base["census"]["files"].items():
            if census["files"].get(path) != item:
                raise OrchestrationError("pilot prefix changed a retained charged-base file identity")
        for path, identity in base["census"]["directories"].items():
            if census["directories"].get(path) != identity:
                raise OrchestrationError("pilot prefix changed a retained publication directory")
        return tuple(expected[:count]), projected

    def _pilot_failure_event(self, manifest, payload, records, authority, registry):
        return LedgerEvent.create(
            run_id=manifest["run_id"], event_id=f"event-{payload['base_event_count'] + 1:04d}",
            timestamp=payload["recorded_at"], actor_role=Role.ORCHESTRATOR,
            state_before="CANDIDATE", requested_state_after="CANDIDATE",
            artifact_hashes=tuple(r.sha256 for r in records),
            code_version=manifest["code_fingerprint"], configuration_hash=manifest["configuration_sha256"],
            dataset_identifiers=manifest["fixture_identifiers"], random_seeds=manifest["random_seeds"],
            evaluator_outputs=(), reason=_PILOT_FAILURE_REASON, event_type="CHECKPOINT",
            prior_event_hash=payload["base_ledger_head_hash"],
            metadata={"schema_version": SCHEMA_VERSION, "initialization": False, "evaluator_keys": [],
                "artifact_types": [r.logical_type for r in records],
                "artifact_record_hashes": [r.record_hash for r in records],
                "artifact_descriptors": [{"logical_type": r.logical_type, "sha256": r.sha256,
                    "registry_record_hash": r.record_hash, "parent_artifacts": list(r.parent_artifacts),
                    "parent_record_hashes": [registry.get_metadata(p).record_hash for p in r.parent_artifacts]}
                    for r in records],
                "resource_authority_checkpoint": {
                    **self._resource_authority_descriptors((authority,))[0],
                    "sequence": authority["sequence"],
                },
                "pilot_call_failure": _PILOT_FAILURE_SCHEMA},
        )

    def _pilot_failure_payload(self, base, records, diagnostic, recorded_at):
        manifest = base["manifest"]
        charge = manifest["artifacts"]["resource_runtime_pilot_charge"]
        return {
            "schema_version": _PILOT_FAILURE_SCHEMA, "kind": "PILOT_CALL_FAILURE",
            "run_id": manifest["run_id"], "state": "CANDIDATE", "owner": "BUILTIN_CANDIDATE_PILOT_V1",
            "request": self._admission_request(manifest), "reason": "OWNED_STAGE_CALL_RAISED",
            "diagnostic_kind": diagnostic, "recorded_at": recorded_at,
            "creation_command": list(base["command"]), "authority_scope": "OPERATIONAL_STICKY_BLOCK",
            "scientific_evidence": False, "retry_allowed": False,
            "charge_artifact_sha256": charge["sha256"], "charge_record_hash": charge["registry_record_hash"],
            "charge_event_id": base["ledger"].events[-1].event_id,
            "prior_authority_sha256": _sha256(_canonical_bytes(base["authorities"][-1])),
            "base_manifest_sha256": _sha256(base["manifest_raw"]),
            "base_manifest_updated_at": manifest["updated_at"],
            "base_event_count": manifest["event_count"], "base_ledger_head_hash": manifest["ledger_head_hash"],
            "base_registry_identities": sorted([[r.sha256, r.record_hash] for r in base["population"].records]),
            "base_file_inventory": self._pilot_inventory(base["census"]),
            "base_checkpoint": base["checkpoint"], "source_context": base["context"],
            "incomplete_output_prefix": [{"ordinal": i, "logical_type": r.logical_type,
                "artifact_sha256": r.sha256, "record_hash": r.record_hash,
                "publication": self._pilot_binding(r, manifest["run_id"])} for i, r in enumerate(records)],
            "prefix_disposition": "INCOMPLETE_STAGE_OUTPUT",
            "runtime_state": manifest["resource_runtime_state"],
            "observation_scope": "UNCHANGED_POST_CHARGE_SNAPSHOT_NOT_FAILURE_TIME",
        }

    def _commit_pilot_failure(self, manifest, base, diagnostic):
        if not self._command_guard_depth():
            raise OrchestrationError("pilot failure publication lost the owning command boundary")
        run_id = base["manifest"]["run_id"]
        registry = self._registry(run_id)
        ledger = EventLedger(self.root, Path("runs") / run_id / "events.jsonl")
        if (tuple(self.command_context) != base["command"]
                or self._pilot_control_snapshot(run_id) != base["control"]
                or _canonical_bytes(self.load_manifest(run_id)) != base["manifest_raw"]
                or ledger.assert_valid() != base["ledger"]
                or self._resource_authority_records(run_id) != base["authorities"]):
            raise OrchestrationError("pilot failure no longer has its retained committed charge")
        population = registry.verify_all(raise_on_error=True)
        census = self._pilot_census(run_id)
        records, projected = self._pilot_prefix(base, population, census)
        # _artifact may raise after registry publication but before projection.
        # Only any subset of independently derived exact prefix bindings may
        # differ in memory. The persisted base is never adopted from the caller.
        supplied = safe_json_loads(_canonical_bytes(manifest))
        for record in records:
            binding = supplied["artifacts"].pop(record.logical_type, None)
            if binding is not None and binding != self._pilot_binding(record, run_id):
                raise OrchestrationError("pilot failed caller substituted an output projection")
        if _canonical_bytes(supplied) != base["manifest_raw"]:
            raise OrchestrationError("pilot failed caller changed non-prefix research state")
        checkpoint, context = self._pilot_base(base["manifest"], registry, base["authorities"],
                                               base["ledger"].events, base["population"].records)
        if checkpoint != base["checkpoint"] or context != base["context"]:
            raise OrchestrationError("pilot failure base changed before publication")
        payload = self._pilot_failure_payload(base, records, diagnostic, _utc_now())
        parents = (payload["charge_artifact_sha256"],
                   base["manifest"]["artifacts"]["frozen_source_inventory"]["sha256"],
                   base["manifest"]["artifacts"]["frozen_configuration_inventory"]["sha256"],
                   *(r.sha256 for r in records))
        record = self._pilot_record(projected, RESOURCE_RUNTIME_PILOT_FAILURE, payload,
                                    Role.ORCHESTRATOR.value, parents, base["command"])
        authority = {"schema_version": SCHEMA_VERSION, "kind": "RESOURCE_RUNTIME_AUTHORITY", "run_id": run_id,
                     "sequence": len(base["authorities"]), "logical_type": RESOURCE_RUNTIME_PILOT_FAILURE,
                     "state_sha256": record.sha256, "state": payload,
                     "prior_authority_sha256": payload["prior_authority_sha256"]}
        event = self._pilot_failure_event(projected, payload, (*records, record), authority, registry)
        raw_ledger = read_confined_bytes(self.root, Path("runs") / run_id / "events.jsonl",
                                        reject_hardlinks=True, max_bytes=MAX_LEDGER_BYTES)
        prospective_raw = raw_ledger + _canonical_bytes(event.to_dict())
        prospective = ledger._validate_bytes(prospective_raw)
        projected["artifacts"][RESOURCE_RUNTIME_PILOT_FAILURE] = self._pilot_binding(record, run_id)
        projected.update(resource_runtime_artifact=RESOURCE_RUNTIME_PILOT_FAILURE,
                         event_count=len(prospective.events), ledger_head_hash=event.event_hash)
        if (population.count + 1 > MAX_REGISTRY_RECORDS or len(base["authorities"]) >= 16
                or len(prospective_raw) > MAX_LEDGER_BYTES or len(prospective.events) > MAX_LEDGER_EVENTS
                or len(_canonical_bytes(authority)) > 1024 * 1024
                or len(_canonical_bytes(projected)) + 4096 > 16 * 1024 * 1024
                or len(_canonical_bytes(projected["artifacts"])) + 8192 > 8 * 1024 * 1024
                or len(tuple((self.root / ".scientist-one-build/checkpoints" / run_id).glob("*.json"))) >= 256
                or not prospective.valid or prospective.events != (*base["ledger"].events, event)):
            raise OrchestrationError("pilot failure publication capacity or event shape differs")
        if (self._pilot_census(run_id) != census or registry.verify_all(raise_on_error=True) != population
                or self._pilot_control_snapshot(run_id) != base["control"]
                or ledger.assert_valid() != base["ledger"]
                or self._resource_authority_records(run_id) != base["authorities"]
                or _canonical_bytes(self.load_manifest(run_id)) != base["manifest_raw"]):
            raise OrchestrationError("pilot failure sources changed before publication")
        if self._persist_resource_authority(projected, RESOURCE_RUNTIME_PILOT_FAILURE, payload) != authority:
            raise OrchestrationError("pilot failure external publication differs")
        binding = self._artifact(projected, RESOURCE_RUNTIME_PILOT_FAILURE, payload,
                                 creator=Role.ORCHESTRATOR.value, parents=parents)
        if binding != self._pilot_binding(record, run_id):
            raise OrchestrationError("pilot failure registry publication differs")
        ledger.append(event)
        self._checkpoint(projected)
        self._replay_pilot_failure(projected, registry, self._resource_authority_records(run_id),
                                   ledger.assert_valid(), registry.verify_all(raise_on_error=True))
        manifest.clear()
        manifest.update(projected)

    def _replay_pilot_failure(self, manifest, registry, authorities, snapshot, population):
        run_id = manifest["run_id"]
        if (tuple(r["logical_type"] for r in authorities) != (
                "resource_runtime_initial", "resource_runtime_pilot_charge", RESOURCE_RUNTIME_PILOT_FAILURE)
                or len(snapshot.events) < 3 or manifest.get("current_state") != "CANDIDATE"
                or manifest.get("terminal_state") is not None
                or manifest.get("resource_runtime_artifact") != RESOURCE_RUNTIME_PILOT_FAILURE):
            raise OrchestrationError("pilot failure is partial, conflicting or followed by work")
        payload = self._json_artifact_payload(manifest, RESOURCE_RUNTIME_PILOT_FAILURE)
        _runtime_state_from_authority_record(authorities[-1])
        if (set(payload) != _PILOT_FAILURE_FIELDS or payload != authorities[-1]["state"]
                or payload["diagnostic_kind"] not in {"RESOURCE_LIMIT_ERROR", "ORDINARY_EXCEPTION"}
                or type(payload["base_event_count"]) is not int
                or payload["base_event_count"] != snapshot.event_count - 1
                or not isinstance(payload["incomplete_output_prefix"], list)
                or len(payload["incomplete_output_prefix"]) > 3):
            raise OrchestrationError("pilot failure shape differs")
        prior = safe_json_loads(_canonical_bytes(manifest))
        prior["artifacts"].pop(RESOURCE_RUNTIME_PILOT_FAILURE)
        prefix_names = tuple(item[0] for item in self._pilot_publications(prior))[:len(payload["incomplete_output_prefix"])]
        for name in prefix_names:
            prior["artifacts"].pop(name)
        prior.update(resource_runtime_artifact="resource_runtime_pilot_charge",
                     resource_runtime_state=authorities[1]["state"],
                     event_count=payload["base_event_count"],
                     ledger_head_hash=snapshot.events[-2].event_hash,
                     updated_at=payload["base_manifest_updated_at"])
        base_records = tuple(r for r in population.records
                             if r.logical_type not in {*prefix_names, RESOURCE_RUNTIME_PILOT_FAILURE})
        checkpoint, context = self._pilot_base(prior, registry, authorities[:2], snapshot.events[:-1],
                                               base_records, replay=True)
        census = self._pilot_census(run_id)
        baseline_paths = self._pilot_expected_files(prior, base_records)
        base_census = {"files": {p: census["files"][p] for p in baseline_paths},
                       "directories": {p: census["directories"][p]
                                       for p in self._pilot_directories(run_id, baseline_paths)}}
        charge_record = registry.get_metadata(authorities[1]["state_sha256"])
        base = {"manifest": prior, "manifest_raw": _canonical_bytes(prior),
                "population": type(population)(True, base_records),
                "ledger": type(snapshot)(True, snapshot.events[:-1], snapshot.events[-2].event_hash),
                "authorities": authorities[:2], "checkpoint": checkpoint, "context": context,
                "census": base_census, "command": charge_record.creation_command}
        failure_records = [r for r in population.records if r.logical_type == RESOURCE_RUNTIME_PILOT_FAILURE]
        if len(failure_records) != 1:
            raise OrchestrationError("pilot failure registry slot is ambiguous")
        failure_record = failure_records[0]
        binding = self._pilot_binding(failure_record, run_id)
        failure_files = {binding["path"], failure_record.path, failure_record.metadata_path}
        prefix_files = {p: v for p, v in census["files"].items() if p not in failure_files}
        prefix_dirs = self._pilot_directories(run_id, prefix_files)
        prefix_census = {"files": prefix_files,
                         "directories": {p: v for p, v in census["directories"].items() if p in prefix_dirs}}
        prefix_population = type(population)(True, tuple(r for r in population.records if r != failure_record))
        records, projected = self._pilot_prefix(base, prefix_population, prefix_census)
        expected_payload = self._pilot_failure_payload(base, records, payload["diagnostic_kind"], payload["recorded_at"])
        if _canonical_bytes(payload) != _canonical_bytes(expected_payload):
            raise OrchestrationError("pilot failure retained base or prefix claim differs")
        parents = (payload["charge_artifact_sha256"],
                   prior["artifacts"]["frozen_source_inventory"]["sha256"],
                   prior["artifacts"]["frozen_configuration_inventory"]["sha256"],
                   *(r.sha256 for r in records))
        expected_record = self._pilot_record(prior, RESOURCE_RUNTIME_PILOT_FAILURE, payload,
                                             Role.ORCHESTRATOR.value, parents, base["command"])
        if (failure_record != expected_record or authorities[-1]["state_sha256"] != failure_record.sha256
                or manifest["artifacts"][RESOURCE_RUNTIME_PILOT_FAILURE] != binding
                or manifest["resource_runtime_state"] != prior["resource_runtime_state"]
                or snapshot.event_count != manifest["event_count"] or snapshot.head_hash != manifest["ledger_head_hash"]
                or snapshot.events[-1] != self._pilot_failure_event(prior, payload, (*records, failure_record), authorities[-1], registry)):
            raise OrchestrationError("pilot failure record, event or charged-state identity differs")
        projected["artifacts"][RESOURCE_RUNTIME_PILOT_FAILURE] = binding
        expected_files = self._pilot_expected_files(projected, population.records)
        if ({p: {"raw": v["raw"], "kind": v["kind"]} for p, v in census["files"].items()} != expected_files
                or set(census["directories"]) != self._pilot_directories(run_id, expected_files)):
            raise OrchestrationError("pilot failure publication census differs")
        self._validate_resource_authority_ledger(authorities, snapshot.events)
        _validate_monotonic_resource_states(authorities)
        self._pilot_checkpoint(manifest, snapshot.events, failure=True)
        self._assert_no_newer_external_checkpoint(manifest)
        return payload

    def _pilot_operation_status(self, manifest, failure=None):
        state = "RESOURCE_OPERATION_BLOCKED" if failure is not None else "RESOURCE_OPERATION_UNRESOLVED"
        slot = RESOURCE_RUNTIME_PILOT_FAILURE if failure is not None else "resource_runtime_pilot_charge"
        return {"status": state, "run_id": manifest["run_id"], "current_state": "CANDIDATE",
                "terminal_state": None, "outcome": state, "mode": manifest.get("mode"),
                "artifact_count": len(manifest["artifacts"]), "event_count": manifest["event_count"],
                "resumable": False, "safe_resume_command": None,
                "operational_blocker": {"artifact_sha256": manifest["artifacts"][slot]["sha256"],
                    "reason": "OWNED_STAGE_CALL_RAISED" if failure is not None else "PILOT_CHARGE_HAS_NO_COMPLETE_SUCCESSOR",
                    "scientific_evidence": False, "automatic_retry": False}}

    def _pilot_historical_stop(self, manifest, registry, authorities, snapshot, population):
        """Retain only an already committed old external-only-charge stop."""
        events, run_id = snapshot.events, manifest["run_id"]
        reason = "external monotonic resource authority detected run rollback"
        if (tuple(r["logical_type"] for r in authorities) != (
                "resource_runtime_initial", "resource_runtime_pilot_charge")
                or len(events) < 2 or manifest.get("current_state") != "STOP_SECURITY"
                or manifest.get("terminal_state") != "STOP_SECURITY"
                or manifest.get("outcome") != "STOP_SECURITY"
                or manifest.get("pending_terminal") is not None
                or type(manifest.get("event_count")) is not int
                or manifest["event_count"] != len(events)
                or manifest.get("ledger_head_hash") != events[-1].event_hash):
            raise OrchestrationError("historical pilot stop projection differs")
        initial, charged = _validate_monotonic_resource_states(authorities)
        if (initial.validity_total_units != 10 or initial.exploratory_used != 0
                or initial.confirmatory_used != 0 or charged.exploratory_used != 2
                or charged.confirmatory_used != 0
                or charged.worker_crashes != initial.worker_crashes
                or charged.progress_elapsed_seconds != initial.progress_elapsed_seconds
                or charged.checkpoint_elapsed_seconds != initial.checkpoint_elapsed_seconds
                or manifest.get("resource_runtime_artifact") != "resource_runtime_initial"
                or _canonical_bytes(manifest.get("resource_runtime_state")) != _canonical_bytes(initial.to_dict())):
            raise OrchestrationError("historical pilot stop did not retain initial runtime")
        resource_names = {r.logical_type for r in population.records if r.logical_type.startswith("resource_runtime_")}
        if (resource_names != {"resource_runtime_initial"}
                or {k for k in manifest["artifacts"] if k.startswith("resource_runtime_")} != resource_names):
            raise OrchestrationError("historical pilot stop has local charge or successor evidence")
        final = events[-1]
        md = thaw_json(final.metadata)
        contract = next(c for c in default_transition_contracts()
                        if c.source is MacroState.CANDIDATE and c.destination is TerminalState.STOP_SECURITY)
        keys = [_terminal_evaluation_key("CANDIDATE", "STOP_SECURITY", evaluator)
                for evaluator in sorted(contract.required_evaluators, key=lambda item: item.value)]
        if (final.event_type != "SECURITY_STOP" or final.state_before is not MacroState.CANDIDATE
                or final.requested_state_after is not TerminalState.STOP_SECURITY
                or final.actor_role is not Role.ORCHESTRATOR or final.reason != reason
                or events[-2].requested_state_after is not MacroState.CANDIDATE
                or any(e.event_type in {"SECURITY_STOP", "CORRECTION"} for e in events[:-1])
                or md.get("artifact_types") != sorted(contract.required_artifact_types)
                or md.get("evaluator_keys") != keys
                or set(md) != {"schema_version", "initialization", "evaluator_keys", "artifact_types",
                              "artifact_record_hashes", "artifact_descriptors", "transition_receipt",
                              "resource_authority_chain"}
                or md["schema_version"] != SCHEMA_VERSION or md["initialization"] is not False
                or md["resource_authority_chain"] != list(self._resource_authority_descriptors(authorities))
                or any(e.metadata.get("resource_authority_chain") is not None for e in events[:-1])):
            raise OrchestrationError("historical pilot stop lacks exact final reconciliation")
        _require_builtin_resource_checkpoint_records(registry, authorities[:1], events[:-1])
        self._validate_resource_authority_ledger(authorities[:1], events[:-1])
        self._validate_resource_authority_ledger(authorities, events)
        self._pilot_base_projection(manifest, registry, events, population.records)
        report = self._json_artifact_payload(manifest, "terminal_report")
        evidence = report.get("evidence")
        expected = {"schema_version": SCHEMA_VERSION, "kind": "TYPED_TERMINAL_REPORT",
                    "run_id": run_id, "source_state": "CANDIDATE", "terminal_state": "STOP_SECURITY",
                    "reason": reason, "evidence": evidence, "honest_negative_or_inconclusive": False}
        record = registry.get_metadata(manifest["artifacts"]["terminal_report"]["sha256"])
        parents = tuple(manifest["artifacts"][name]["sha256"]
                        for name in sorted(manifest["artifacts"]) if name != "terminal_report")
        if (not isinstance(evidence, dict) or set(evidence) != {"resource_authority", "detail"}
                or evidence["resource_authority"] != "ROLLBACK_OR_STALE_PROJECTION"
                or not isinstance(evidence["detail"], str)
                or _canonical_bytes(report) != _canonical_bytes(expected)
                or registry.get_bytes(record.sha256) != _canonical_bytes(expected)
                or record.creator_role is not Role.ORCHESTRATOR or record.parent_artifacts != parents):
            raise OrchestrationError("historical pilot stop report owner differs")
        census = self._pilot_census(run_id)
        expected_files = self._pilot_expected_files(manifest, population.records)
        if ({p: {"raw": v["raw"], "kind": v["kind"]} for p, v in census["files"].items()} != expected_files
                or set(census["directories"]) != self._pilot_directories(run_id, expected_files)):
            raise OrchestrationError("historical pilot stop has unbound publication bytes")
        self._pilot_checkpoint(manifest, events, terminal="STOP_SECURITY")
        self._assert_no_newer_external_checkpoint(manifest)
        # Validate every surviving preceding checkpoint, not merely selection of
        # the newest valid one. This cannot repair, quarantine or finish a suffix.
        relative = Path(".scientist-one-build/checkpoints") / run_id
        fd = open_confined_directory_fd(self.root, relative, create=False)
        try:
            with os.scandir(fd) as entries:
                names = []
                for entry in entries:
                    if len(names) >= 256:
                        raise OrchestrationError("historical checkpoint population exceeds bound")
                    names.append(entry.name)
            seen = set()
            for name in names:
                value = _read_json(self.root / relative / name)
                matching = [i for i, e in enumerate(events) if e.event_id == value["event_id"]]
                if len(matching) != 1 or value["event_id"] in seen:
                    raise OrchestrationError("historical checkpoint event is absent or duplicated")
                seen.add(value["event_id"])
                index = matching[0]
                artifacts, records, pointer = {}, {}, None
                for event in events[:index + 1]:
                    metadata = event.metadata
                    for logical, digest, record_hash in zip(
                            metadata["artifact_types"], event.artifact_hashes,
                            metadata["artifact_record_hashes"], strict=True):
                        artifacts[logical], records[logical] = digest, record_hash
                        if logical.startswith("resource_runtime_"):
                            pointer = logical
                if (name != value["checkpoint_id"] + ".json"
                        or value["ledger_head_hash"] != events[index].event_hash
                        or value["state"] != events[index].requested_state_after.value
                        or value["artifact_hashes"] != artifacts or value["artifact_record_hashes"] != records
                        or value["resource_runtime_artifact"] != pointer
                        or not isinstance(value["created_at"], str) or not value["created_at"]):
                    raise OrchestrationError("historical checkpoint prefix projection differs")
            if not {events[-2].event_id, final.event_id}.issubset(seen):
                raise OrchestrationError("historical stop lacks its actual preceding or terminal checkpoint")
        finally:
            os.close(fd)
        return {"status": "STOP_SECURITY", "run_id": run_id, "current_state": "STOP_SECURITY",
                "terminal_state": "STOP_SECURITY", "outcome": "STOP_SECURITY", "mode": manifest["mode"],
                "artifact_count": len(manifest["artifacts"]), "event_count": len(events),
                "resumable": False, "safe_resume_command": None, "persisted": True,
                "authority_channel": "EXISTING_RESOURCE_ROLLBACK_TERMINAL"}


    @staticmethod
    def _pilot_pair_event_shape(events, direct, state):
        """Consecutive resource-only events from the existing charge owner."""
        charge_index, completion_index = direct[1][0], direct[2][0]
        if completion_index != charge_index + 1:
            raise OrchestrationError("pilot resource pair is not consecutive")
        keys = {"schema_version", "initialization", "evaluator_keys", "artifact_types",
                "artifact_record_hashes", "artifact_descriptors", "resource_authority_checkpoint"}
        for index, logical, reason in (
                (charge_index, "resource_runtime_pilot_charge",
                 "atomic PILOT validity charge persisted before execution"),
                (completion_index, "resource_runtime_pilot_completion",
                 "PILOT resource state persisted after execution")):
            event = events[index]
            metadata = thaw_json(event.metadata)
            if (event.state_before is not state or event.requested_state_after is not state
                    or event.actor_role is not Role.ORCHESTRATOR or event.event_type != "CHECKPOINT"
                    or event.reason != reason or event.evaluator_outputs
                    or len(event.artifact_hashes) != 1 or set(metadata) != keys
                    or metadata["schema_version"] != SCHEMA_VERSION
                    or metadata["initialization"] is not False or metadata["evaluator_keys"] != []
                    or metadata["artifact_types"] != [logical]):
                raise OrchestrationError("pilot resource pair event shape differs")

    def _calibrate_pilot_pair(self, manifest, registry, authorities, events, population, direct, states):
        """Existing operational wall-pair compatibility, never scientific work."""
        self._pilot_pair_event_shape(events, direct, MacroState.CALIBRATE)
        initial, charged, completed = states[:3]
        if (initial.exploratory_used or initial.confirmatory_used
                or initial.validity_total_units is None
                or charged.confirmatory_used or completed.confirmatory_used
                or completed.exploratory_used != charged.exploratory_used
                or charged.worker_crashes != initial.worker_crashes
                or completed.worker_crashes != charged.worker_crashes
                or charged.progress_elapsed_seconds != initial.progress_elapsed_seconds
                or charged.checkpoint_elapsed_seconds != initial.checkpoint_elapsed_seconds
                or completed.checkpoint_elapsed_seconds != charged.checkpoint_elapsed_seconds):
            raise OrchestrationError("operational CALIBRATE pair accounting differs")
        config = self._load_frozen_resource_config(manifest)
        if config is None or charged.config_sha256 != resource_config_sha256(config):
            raise OrchestrationError("operational CALIBRATE pair configuration differs")
        # Restore the existing arithmetic owner only; no observation or charge.
        ValidityBudget(initial.validity_total_units, config.validity_reserve_fraction,
                       exploratory_used=charged.exploratory_used, confirmatory_used=0)
        stages = tuple(r["logical_type"] for r in authorities)
        allowed = ("resource_runtime_initial", "resource_runtime_pilot_charge",
                   "resource_runtime_pilot_completion")
        if stages not in {allowed, (*allowed, RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE)}:
            raise OrchestrationError("operational CALIBRATE pair has a scientific successor")
        names = set(manifest["artifacts"]) | {r.logical_type for r in population.records}
        evaluator_keys = set(manifest["evaluator_decisions"])
        for event in events:
            names.update(event.metadata.get("artifact_types", ()))
            evaluator_keys.update(event.metadata.get("evaluator_keys", ()))
            if (event.state_before.value not in {"CALIBRATE", *TERMINAL_STATES}
                    or event.requested_state_after.value not in {"CALIBRATE", *TERMINAL_STATES}
                    or event.event_type == "CONFIRMATORY_STARTED"
                    or event.metadata.get("execution_kind") == "SIMULATED_ARCHITECTURE_CONTROL_STARTED"):
                raise OrchestrationError("operational CALIBRATE pair contains scientific stages")
        prohibited = {"pilot_report", "midrun_review", "blind_interpretation",
                      "custody_record", RESOURCE_RUNTIME_PILOT_FAILURE, RESOURCE_RUNTIME_ADMISSION_REFUSAL}
        if (names.intersection(prohibited)
                or any("CONFIRM" in key or key.endswith(":CANDIDATE") for key in evaluator_keys)
                or any(name.startswith(("resource_runtime_confirmatory", "custody_")) for name in names)
                or not self._validate_live_custody(manifest)):
            raise OrchestrationError("operational CALIBRATE pair contains scientific authority claims")

    def _pilot_evaluation_live(self, manifest):
        # These namespaces are not included in control/publication census.
        if ("custody_record" in manifest["artifacts"]
                or not self._validate_live_custody(manifest)
                or not self._validate_live_inventories(manifest)):
            raise OrchestrationError("pending pilot evaluation live inputs or custody changed")

    def _pilot_evaluation_checkpoints(self, manifest, events, control):
        """Read every actual earlier checkpoint; no recovery or adoption."""
        self._assert_no_newer_external_checkpoint(manifest)
        prefix = (Path(".scientist-one-build/checkpoints") / manifest["run_id"]).as_posix() + "/"
        seen = set()
        for path, (raw, _identity) in control["files"].items():
            if not path.startswith(prefix):
                continue
            value = safe_json_loads(raw)
            matching = [i for i, e in enumerate(events) if e.event_id == value["event_id"]]
            if len(matching) != 1 or value["event_id"] in seen:
                raise OrchestrationError("pending pilot checkpoint slot is absent or duplicated")
            index = matching[0]
            seen.add(value["event_id"])
            # Neither charge nor completion emits a local/external checkpoint.
            if index >= len(events) - 2:
                raise OrchestrationError("pending pilot has an unowned resource checkpoint")
            artifacts, records, pointer = {}, {}, None
            for event in events[:index + 1]:
                metadata = event.metadata
                for logical, digest, record_hash in zip(
                        metadata["artifact_types"], event.artifact_hashes,
                        metadata["artifact_record_hashes"], strict=True):
                    artifacts[logical], records[logical] = digest, record_hash
                    if logical.startswith("resource_runtime_"):
                        pointer = logical
            if (Path(path).name != value["checkpoint_id"] + ".json"
                    or value["ledger_head_hash"] != events[index].event_hash
                    or value["state"] != events[index].requested_state_after.value
                    or value["artifact_hashes"] != artifacts or value["artifact_record_hashes"] != records
                    or value["resource_runtime_artifact"] != pointer
                    or not isinstance(value["created_at"], str) or not value["created_at"]):
                raise OrchestrationError("pending pilot checkpoint prefix projection differs")
        if events[-3].event_id not in seen:
            raise OrchestrationError("pending pilot lacks its actual earlier checkpoint")

    def _pilot_evaluation_context(self, manifest):
        """Ephemeral join, only after the complete negative PILOT disposition.

        An absent manifest completion key makes this evaluator lookup
        inapplicable; it is not proof of no work or admission/recovery authority.
        Every guarded caller must first run _pilot_operation_disposition, whose
        independent channels detect hidden, partial and corrupt PILOT markers.
        """
        if "resource_runtime_pilot_completion" not in manifest["artifacts"]:
            return None
        authorities = self._resource_authority_records(manifest["run_id"])
        pair = ("resource_runtime_initial", "resource_runtime_pilot_charge",
                "resource_runtime_pilot_completion")
        if tuple(r["logical_type"] for r in authorities[:3]) != pair:
            return None
        try:
            run_id = manifest["run_id"]
            control = self._pilot_control_snapshot(run_id)
            registry = self._registry(run_id)
            population = registry.verify_all(raise_on_error=True)
            events = EventLedger(self.root, Path("runs") / run_id / "events.jsonl").assert_valid().events
            direct = _require_uncorrected_direct_resource_checkpoints(authorities[:3], events)
            completion_index = direct[-1][0]
            if events[completion_index].state_before is not MacroState.CANDIDATE:
                return None
            if completion_index + 1 < len(events):
                successor = events[completion_index + 1]
                # Existing completed typed successors keep their original owner.
                # The preceding negative router already joined the full current
                # projection; unknown same-stage events are not such an edge.
                if (successor.event_type in {"TRANSITION", "SECURITY_STOP"}
                        and successor.state_before is MacroState.CANDIDATE
                        and successor.requested_state_after.value in {"CONFIRM", *TERMINAL_STATES}):
                    return None
                raise OrchestrationError("pending pilot evaluation has an unknown successor")
            if (tuple(r["logical_type"] for r in authorities) != pair
                    or manifest.get("current_state") != "CANDIDATE"
                    or manifest.get("terminal_state") is not None or manifest.get("pending_terminal") is not None
                    or manifest.get("outcome") != "IN_PROGRESS"):
                raise OrchestrationError("pending pilot evaluation stage differs")
            census = self._pilot_census(run_id)
            manifest_path = (Path("runs") / run_id / "manifest.json").as_posix()
            if control["files"][manifest_path][0] != _canonical_bytes(manifest):
                raise OrchestrationError("pending pilot differs from its saved manifest")
            self._pilot_completed_projection(manifest, registry, authorities, events)
            self._pilot_pair_event_shape(events, direct, MacroState.CANDIDATE)
            if (len(events) < 3 or events[-3].requested_state_after is not MacroState.CANDIDATE
                    or events[-3].state_before is not MacroState.DISCOVER
                    or events[-3].event_type != "TRANSITION"):
                raise OrchestrationError("pending pilot evaluation lacks its prior typed stage")
            _initial, charged, completed = _validate_monotonic_resource_states(authorities)
            if (completed.exploratory_used != charged.exploratory_used
                    or completed.confirmatory_used != charged.confirmatory_used
                    or completed.worker_crashes != charged.worker_crashes
                    or completed.checkpoint_elapsed_seconds != charged.checkpoint_elapsed_seconds):
                raise OrchestrationError("pending pilot completion changed charge accounting")
            names = ("pilot_report", "midrun_review", "blind_interpretation")
            prior = safe_json_loads(_canonical_bytes(manifest))
            removed = {prior["artifacts"].pop(name)["sha256"] for name in (*names, pair[-1])}
            if len(removed) != 4:
                raise OrchestrationError("pending pilot output population aliases")
            prior.update(resource_runtime_artifact=pair[1], resource_runtime_state=charged.to_dict(),
                         event_count=len(events) - 1, ledger_head_hash=events[-2].event_hash)
            base_records = tuple(r for r in population.records if r.sha256 not in removed)
            self._pilot_base(prior, registry, authorities[:2], events[:-1], base_records)
            charge_record = registry.get_metadata(authorities[1]["state_sha256"])
            expected = tuple(self._pilot_record(prior, name, payload, creator, parents,
                                               charge_record.creation_command)
                             for name, payload, creator, parents in self._pilot_publications(prior))
            completion = self._pilot_record(
                prior, pair[-1], completed.to_dict(), Role.ORCHESTRATOR.value,
                (charge_record.sha256,), charge_record.creation_command)
            expected += (completion,)
            observed = {r.sha256: r for r in population.records}
            if (len(observed) != len(base_records) + 4
                    or any(observed.get(r.sha256) != r for r in expected)
                    or any(manifest["artifacts"].get(r.logical_type)
                           != self._pilot_binding(r, run_id) for r in expected)):
                raise OrchestrationError("pending pilot source-derived outputs differ")
            expected_files = self._pilot_expected_files(manifest, population.records)
            if ({p: {"raw": v["raw"], "kind": v["kind"]} for p, v in census["files"].items()} != expected_files
                    or set(census["directories"]) != self._pilot_directories(run_id, expected_files)):
                raise OrchestrationError("pending pilot output census differs")
            self._pilot_evaluation_checkpoints(manifest, events, control)
            self._pilot_evaluation_live(manifest)
            if (control != self._pilot_control_snapshot(run_id) or census != self._pilot_census(run_id)):
                raise OrchestrationError("pending pilot inputs changed during recognition")
            # Explicit live/absence close after all potentially long readers.
            self._pilot_evaluation_live(manifest)
            return {"manifest": safe_json_loads(_canonical_bytes(manifest)),
                    "control": control, "census": census}
        except OrchestrationError:
            raise
        except Exception as exc:
            raise OrchestrationError("pending pilot evaluation cannot be joined") from exc

    def _pilot_evaluation_status(self, context):
        manifest = context["manifest"]
        record = manifest["artifacts"]["resource_runtime_pilot_completion"]
        return {"status": "CANDIDATE_EVALUATION_PENDING", "run_id": manifest["run_id"],
                "current_state": "CANDIDATE", "terminal_state": None, "outcome": "IN_PROGRESS",
                "mode": manifest["mode"], "resumable": True, "persisted": False,
                "safe_resume_command": ["python3", "-I", "-S", "-B",
                                        "scripts/scientist_one_cli.py", "resume", manifest["run_id"]],
                "artifact_count": len(manifest["artifacts"]),
                "continuation_scope": "EVALUATOR_ONLY", "scientific_evidence": False,
                "event_count": manifest["event_count"], "ledger_head_hash": manifest["ledger_head_hash"],
                "completion_artifact_sha256": record["sha256"],
                "completion_record_hash": record["registry_record_hash"]}

    def _continue_pilot_evaluation(self, manifest, context):
        self._resource_controller(manifest)  # Existing restoration, not admission.
        self._evaluate_candidate(manifest)
        keys = ("E0:CANDIDATE", "E2:CANDIDATE", "E3:CANDIDATE")
        expected = safe_json_loads(_canonical_bytes(context["manifest"]))
        for key in keys:
            if key in expected["evaluator_decisions"] or key not in manifest["evaluator_decisions"]:
                raise OrchestrationError("pending pilot evaluator result population differs")
            expected["evaluator_decisions"][key] = manifest["evaluator_decisions"][key]
        if _canonical_bytes(manifest) != _canonical_bytes(expected):
            raise OrchestrationError("pending pilot evaluator changed unrelated working state")
        run_id = manifest["run_id"]
        if (context["control"] != self._pilot_control_snapshot(run_id)
                or context["census"] != self._pilot_census(run_id)):
            raise OrchestrationError("pending pilot evaluator changed committed inputs")
        self._pilot_evaluation_live(manifest)

    def _pilot_completed_projection(self, manifest, registry, authorities, events):
        """Join current resource projection before returning to its existing owner."""
        if (not events or type(manifest.get("event_count")) is not int
                or manifest["event_count"] != len(events)
                or manifest.get("ledger_head_hash") != events[-1].event_hash):
            raise OrchestrationError("completed pilot current ledger projection differs")
        latest = authorities[-1]
        # The admission owner validates its own closed wrapper, source manifest,
        # checkpoint and publication prefix. It is not a plain runtime record.
        refusal = self._resource_admission_refusal(manifest)
        if refusal is not None:
            return
        stages = tuple(item["logical_type"] for item in authorities)
        observed_wall = stages[-1] == RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
        plain = stages[:-1] if observed_wall else stages
        existing_confirm_charge = (
            not observed_wall and plain == (
                "resource_runtime_initial", "resource_runtime_pilot_charge",
                "resource_runtime_pilot_completion", "resource_runtime_confirmatory_charge")
        )
        if plain not in _LEGACY_RESOURCE_RUNTIME_STAGE_SEQUENCES and not existing_confirm_charge:
            raise OrchestrationError("completed pilot has no applicable built-in successor")
        direct = _require_builtin_resource_checkpoint_records(registry, authorities, events)
        self._validate_resource_authority_ledger(authorities, events)
        states = _validate_monotonic_resource_states(authorities)
        if (manifest.get("resource_runtime_artifact") != latest["logical_type"]
                or _canonical_bytes(manifest.get("resource_runtime_state")) != _canonical_bytes(states[-1].to_dict())):
            raise OrchestrationError("completed pilot current runtime projection differs")
        for authority, (_index, event, _position, _hash) in zip(authorities, direct, strict=True):
            record = registry.get_metadata(authority["state_sha256"])
            binding = self._pilot_binding(record, manifest["run_id"], event.state_before.value.lower())
            if authority["logical_type"] == RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE:
                binding["path"] = record.path
            if (_canonical_bytes(manifest["artifacts"].get(authority["logical_type"])) != _canonical_bytes(binding)
                    or read_confined_bytes(self.root, binding["path"], reject_hardlinks=True,
                                           max_bytes=MAX_ARTIFACT_OBJECT_BYTES) != registry.get_bytes(record.sha256)):
                raise OrchestrationError("completed pilot resource binding differs")
        first = events[0]
        for event in events:
            if (event.run_id != manifest["run_id"] or event.code_version != first.code_version
                    or event.configuration_hash != first.configuration_hash
                    or event.dataset_identifiers != first.dataset_identifiers
                    or event.random_seeds != first.random_seeds
                    or event.code_version != manifest["code_fingerprint"]
                    or event.configuration_hash != manifest["configuration_sha256"]
                    or tuple(manifest["fixture_identifiers"]) != event.dataset_identifiers
                    or tuple(manifest["random_seeds"]) != event.random_seeds):
                raise OrchestrationError("completed pilot current initialization context differs")
        receipts = validate_legacy_transition_prefix(tuple(e.to_dict() for e in events))
        state = events[-1].requested_state_after.value
        terminal = state if state in TERMINAL_STATES else None
        outcome = "COMPLETE_DEMO_ONLY" if terminal == "READY_FOR_HUMAN_REVIEW" else terminal or "IN_PROGRESS"
        if (manifest.get("current_state") != state or manifest.get("terminal_state") != terminal
                or manifest.get("outcome") != outcome
                or tuple(manifest["typed_transition_receipts"]) != tuple(r.to_dict() for r in receipts)
                or manifest["completed_transitions"] != [f"{r.prior_state.value}->{r.current_state.value}" for r in receipts]
                or StateController(initial_state=parse_state(state), artifact_registry=registry,
                                   prior_receipts=receipts).current_state != parse_state(state)):
            raise OrchestrationError("completed pilot current typed projection differs")
        self._assert_no_newer_external_checkpoint(manifest)

    def _pilot_operation_disposition(self, manifest):
        """Negative routing only. Missing completion never witnesses an exception."""
        run_id = manifest["run_id"]
        names = {"resource_runtime_pilot_charge", "resource_runtime_pilot_completion", RESOURCE_RUNTIME_PILOT_FAILURE}
        markers = set(manifest.get("artifacts", {})).intersection(names)
        if manifest.get("resource_runtime_artifact") in names:
            markers.add(manifest["resource_runtime_artifact"])
        errors, authorities, population, snapshot = [], (), None, None
        try:
            authorities = self._resource_authority_records(run_id)
            markers.update(r["logical_type"] for r in authorities if r["logical_type"] in names)
        except Exception as exc:
            errors.append(exc)
            # A corrupt early authority file must not conceal later independent
            # marker records. Read bounded individual existing files only.
            directory = Path(".scientist-one-build/resource-authority") / run_id
            try:
                fd = open_confined_directory_fd(self.root, directory, create=False)
                try:
                    with os.scandir(fd) as entries:
                        files = []
                        for entry in entries:
                            if len(files) >= 16:
                                raise OrchestrationError("pilot authority marker population exceeds bound")
                            files.append(entry.name)
                    for name in files:
                        try:
                            raw = read_confined_bytes(self.root, directory / name, reject_hardlinks=True, max_bytes=1024 * 1024)
                            value = safe_json_loads(raw)
                            if isinstance(value, dict) and value.get("logical_type") in names:
                                markers.add(value["logical_type"])
                        except Exception:
                            pass
                    if len(files) > 1 and manifest.get("current_state") == "CANDIDATE":
                        markers.add("unreadable_post_initial_authority")
                finally:
                    os.close(fd)
            except Exception as marker_error:
                errors.append(marker_error)
        registry = None
        try:
            # The registry reader initializes its directories. Require those
            # already-owned namespaces first so a damaged negative path cannot
            # cause that initializer to recreate them.
            for suffix in ("registry/objects", "registry/metadata"):
                fd = open_confined_directory_fd(self.root, Path("runs") / run_id / suffix, create=False)
                os.close(fd)
            registry = self._registry(run_id)
            population = registry.verify_all(raise_on_error=False)
            markers.update(r.logical_type for r in population.records if r.logical_type in names)
            if not population.valid:
                errors.append(OrchestrationError("pilot registry marker population is corrupt"))
        except Exception as exc:
            errors.append(exc)
        try:
            snapshot = EventLedger(self.root, Path("runs") / run_id / "events.jsonl").validate()
            for event in snapshot.events:
                markers.update(set(event.metadata.get("artifact_types", ())).intersection(names))
                if event.metadata.get("pilot_call_failure") is not None:
                    markers.add(RESOURCE_RUNTIME_PILOT_FAILURE)
            if not snapshot.valid:
                errors.append(OrchestrationError("pilot ledger marker population is corrupt"))
        except Exception as exc:
            errors.append(exc)
        if not markers:
            return None
        if errors:
            raise OrchestrationError("recognized pilot operation has incomplete or corrupt authority") from errors[0]
        assert registry is not None and population is not None and snapshot is not None
        try:
            stages = tuple(r["logical_type"] for r in authorities)
            failure = RESOURCE_RUNTIME_PILOT_FAILURE in markers
            if failure:
                payload = self._replay_pilot_failure(manifest, registry, authorities, snapshot, population)
                return self._pilot_operation_status(manifest, payload)
            if stages[:3] == ("resource_runtime_initial", "resource_runtime_pilot_charge", "resource_runtime_pilot_completion"):
                direct = _require_uncorrected_direct_resource_checkpoints(authorities[:3], snapshot.events)
                completion_index = direct[-1][0]
                _require_exact_resource_checkpoint_closure(registry, authorities[:3], snapshot.events[:completion_index + 1])
                self._validate_resource_authority_ledger(authorities[:3], snapshot.events[:completion_index + 1])
                states = _validate_monotonic_resource_states(authorities[:3])
                if manifest["event_count"] < completion_index + 1:
                    raise OrchestrationError("pilot completion accounting or manifest commitment differs")
                if (direct[1][1].state_before is MacroState.CALIBRATE
                        and direct[2][1].state_before is MacroState.CALIBRATE):
                    self._calibrate_pilot_pair(
                        manifest, registry, authorities, snapshot.events, population, direct, states)
                elif (states[1].exploratory_used != 2 or states[2].exploratory_used != 2
                        or states[1].confirmatory_used != 0 or states[2].confirmatory_used != 0
                        or direct[1][1].state_before is not MacroState.CANDIDATE
                        or direct[2][1].state_before is not MacroState.CANDIDATE):
                    raise OrchestrationError("pilot completion accounting or manifest commitment differs")
                for authority in authorities[:3]:
                    stored = registry.get_metadata(authority["state_sha256"])
                    binding = manifest.get("artifacts", {}).get(authority["logical_type"])
                    if (not isinstance(binding, dict) or binding.get("sha256") != stored.sha256
                            or binding.get("registry_record_hash") != stored.record_hash):
                        raise OrchestrationError("pilot completion projection is absent or substituted")
                # A completed PILOT may precede an exact later CONFIRM refusal.
                # Its independent admission validator remains the authority for it.
                self._pilot_completed_projection(manifest, registry, authorities, snapshot.events)
                return None
            if stages != ("resource_runtime_initial", "resource_runtime_pilot_charge"):
                raise OrchestrationError("pilot charge has an incompatible or partial successor")
            if (manifest.get("terminal_state") is not None or manifest.get("current_state") in TERMINAL_STATES
                    or any(e.event_type == "SECURITY_STOP" for e in snapshot.events)):
                return self._pilot_historical_stop(manifest, registry, authorities, snapshot, population)
            if RESOURCE_RUNTIME_ADMISSION_REFUSAL in manifest.get("artifacts", {}) or any(
                    r.logical_type == RESOURCE_RUNTIME_ADMISSION_REFUSAL for r in population.records):
                raise OrchestrationError("open pilot conflicts with admission refusal")
            base_records = tuple(r for r in population.records if r.sha256 in {
                item["sha256"] for item in manifest["artifacts"].values()})
            self._pilot_base(manifest, registry, authorities, snapshot.events, base_records)
            # No positive output adoption: a valid open charge is a durable reason
            # not to run, including when no failure record publication ever began.
            return self._pilot_operation_status(manifest)
        except OrchestrationError:
            raise
        except Exception as exc:
            raise OrchestrationError("recognized pilot operation cannot be replayed") from exc

    def _admission_request(self, manifest: Mapping[str, Any]) -> dict[str, Any]:
        state = manifest.get("current_state")
        if state == "CANDIDATE":
            suffix, stage, units = "pilot", "PILOT", 2
        elif state == "CONFIRM":
            suffix, stage, units = "confirmatory", "CONFIRMATORY", 4
        else:
            raise OrchestrationError("durable refusal is not an ordinary resource callsite")
        return {"experiment_id": f"{manifest['run_id']}:{suffix}",
                "cpu_workers": 1, "gpu_jobs": 0, "estimated_artifact_bytes": 0,
                "validity_stage": stage, "validity_units": units}

    def _admission_sources(self, manifest, registry, authorities, events):
        if not authorities or not events:
            raise OrchestrationError("admission refusal lacks initialized sources")
        _require_exact_resource_checkpoint_closure(registry, authorities, events)
        self._validate_resource_authority_ledger(authorities, events)
        prior = _validate_monotonic_resource_states(authorities)[-1]
        expected_stages = ("resource_runtime_initial",)
        expected_used = 0
        if manifest.get("current_state") == "CONFIRM":
            expected_stages += ("resource_runtime_pilot_charge", "resource_runtime_pilot_completion")
            expected_used = 2
        if (manifest.get("current_state") not in {"CANDIDATE", "CONFIRM"}
                or tuple(r["logical_type"] for r in authorities) != expected_stages
                or prior.validity_total_units != 10
                or prior.exploratory_used != expected_used or prior.confirmatory_used != 0):
            raise OrchestrationError("admission prior resource stage is not the ordinary callsite")
        source = self._json_artifact_payload(manifest, "frozen_source_inventory")
        configuration = self._json_artifact_payload(manifest, "frozen_configuration_inventory")
        initial = events[0]
        fixture_ids = manifest.get("fixture_identifiers")
        random_seeds = manifest.get("random_seeds")
        if (_source_inventory(self.root) != source
                or _configuration_inventory(self.root) != configuration
                or source["aggregate_sha256"] != manifest["code_fingerprint"]
                or configuration["aggregate_sha256"] != manifest["configuration_sha256"]
                or manifest["code_fingerprint"] != initial.code_version
                or manifest["configuration_sha256"] != initial.configuration_hash
                or not isinstance(fixture_ids, (list, tuple))
                or tuple(fixture_ids) != initial.dataset_identifiers
                or not isinstance(random_seeds, (list, tuple))
                or tuple(random_seeds) != initial.random_seeds
                or events[-1].requested_state_after.value != manifest["current_state"]
                or events[-1].event_hash != manifest["ledger_head_hash"]
                or len(events) != manifest["event_count"]
                or manifest.get("terminal_state") is not None
                or manifest.get("outcome") != "IN_PROGRESS"
                or manifest.get("resource_runtime_artifact") != authorities[-1]["logical_type"]
                or manifest.get("resource_runtime_state") != prior.to_dict()):
            raise OrchestrationError("admission source projection is stale or substituted")
        validation = self._foundation_ledger_validation(
            self.root / "runs" / manifest["run_id"] / "events.jsonl"
        )
        # During replay this validates the full ledger, including the refusal.
        if not validation.valid:
            raise OrchestrationError("admission ledger has invalid transition authority")
        return self._load_frozen_resource_config(manifest), prior

    def _admission_record(self, registry, payload, parents, created_at):
        raw = _canonical_bytes(payload)
        digest = _sha256(raw)
        path = registry._object_relative(digest).as_posix()
        return ArtifactRecord(
            sha256=digest, path=path, relative_path=path,
            metadata_path=registry._metadata_relative(digest).as_posix(),
            logical_type=RESOURCE_RUNTIME_ADMISSION_REFUSAL, schema_version=SCHEMA_VERSION,
            mime_type="application/json", size=len(raw),
            origin=_BUILTIN_OFFLINE_ARTIFACT_ORIGIN, creator_role=Role.ORCHESTRATOR,
            creation_command=tuple(payload["creation_command"]),
            parent_artifacts=parents, validation_result="PASS", frozen=True,
            created_at=created_at,
        )

    def _admission_event(self, manifest, payload, record, authority, registry):
        parents = record.parent_artifacts
        return LedgerEvent.create(
            run_id=manifest["run_id"], event_id=f"event-{payload['source_event_count'] + 1:04d}",
            timestamp=payload["recorded_at"], actor_role=Role.ORCHESTRATOR,
            state_before=manifest["current_state"], requested_state_after=manifest["current_state"],
            artifact_hashes=(record.sha256,), code_version=manifest["code_fingerprint"],
            configuration_hash=manifest["configuration_sha256"],
            dataset_identifiers=manifest["fixture_identifiers"], random_seeds=manifest["random_seeds"],
            evaluator_outputs=(), reason=_RESOURCE_ADMISSION_REASON, event_type="CHECKPOINT",
            prior_event_hash=payload["source_ledger_head_hash"],
            metadata={
                "schema_version": SCHEMA_VERSION, "initialization": False, "evaluator_keys": [],
                "artifact_types": [RESOURCE_RUNTIME_ADMISSION_REFUSAL],
                "artifact_record_hashes": [record.record_hash],
                "artifact_descriptors": [{
                    "logical_type": RESOURCE_RUNTIME_ADMISSION_REFUSAL, "sha256": record.sha256,
                    "registry_record_hash": record.record_hash, "parent_artifacts": list(parents),
                    "parent_record_hashes": [registry.get_metadata(p).record_hash for p in parents],
                }],
                "resource_authority_checkpoint": {
                    **self._resource_authority_descriptors((authority,))[0],
                    "sequence": authority["sequence"],
                },
                "resource_admission_refusal": _RESOURCE_ADMISSION_SCHEMA,
            },
        )

    def _resource_admission_refusal(self, manifest):
        """Exact read-only sticky commitment; never repair a partial publication."""
        run_id = str(manifest["run_id"])
        hint = (RESOURCE_RUNTIME_ADMISSION_REFUSAL in manifest.get("artifacts", {})
                or manifest.get("resource_runtime_artifact") == RESOURCE_RUNTIME_ADMISSION_REFUSAL)
        errors = []
        authorities, slots, selected, marked = (), (), (), ()
        population = snapshot = None
        try:
            authorities = self._resource_authority_records(run_id)
            slots = tuple(r for r in authorities
                          if r["logical_type"] == RESOURCE_RUNTIME_ADMISSION_REFUSAL)
        except OrchestrationError as exc:
            errors.append(exc)
        registry = self._registry(run_id)
        try:
            # Collect validated surviving records even if another registry
            # entry is corrupt. They are refusal markers only, never a grant
            # of complete-registry authority; every error still fails below.
            population = registry.verify_all(raise_on_error=False)
            selected = tuple(r for r in population.records
                             if r.logical_type == RESOURCE_RUNTIME_ADMISSION_REFUSAL)
            if not population.valid:
                errors.append(OrchestrationError(f"admission registry validation failed: {population.errors!r}"))
        except Exception as exc:
            errors.append(exc)
        ledger = EventLedger(self.root, Path("runs") / run_id / "events.jsonl")
        try:
            # validate retains a valid event prefix without repairing it.
            snapshot = ledger.validate()
            marked = tuple(e for e in snapshot.events
                           if e.metadata.get("resource_admission_refusal") is not None
                           or RESOURCE_RUNTIME_ADMISSION_REFUSAL in e.metadata.get("artifact_types", ()))
            if not snapshot.valid:
                errors.append(OrchestrationError(f"admission ledger validation failed: {snapshot.error}"))
        except Exception as exc:
            errors.append(exc)
        if not (hint or slots or selected or marked):
            # Only after every independently available marker channel has
            # been examined may a truly unrecognized history retain its
            # existing legacy corruption/rollback disposition.
            return None
        if errors:
            raise OrchestrationError("recognized admission refusal has incomplete or corrupt authority") from errors[0]
        assert population is not None and snapshot is not None
        if (len(slots) != 1 or len(selected) != 1 or len(marked) != 1
                or authorities[-1] != slots[0] or snapshot.events[-1] != marked[0]):
            raise OrchestrationError("admission refusal is partial, duplicated or followed by work")
        slot, record, event = slots[0], selected[0], marked[0]
        payload = self._json_artifact_payload(manifest, RESOURCE_RUNTIME_ADMISSION_REFUSAL)
        if (set(payload) != _RESOURCE_ADMISSION_FIELDS or payload["schema_version"] != _RESOURCE_ADMISSION_SCHEMA
                or payload["kind"] != "RESOURCE_ADMISSION_REFUSAL"
                or payload["run_id"] != run_id or payload["state"] != manifest["current_state"]
                or payload["authority_scope"] != "OPERATIONAL_STICKY_BLOCK"
                or payload["scientific_evidence"] is not False
                or type(payload["source_event_count"]) is not int
                or payload["source_event_count"] < 1
                or payload["source_event_count"] != snapshot.event_count - 1
                or payload["source_ledger_head_hash"] != snapshot.events[-2].event_hash
                or not _supported_builtin_resource_command(payload["creation_command"], run_id=run_id)):
            raise OrchestrationError("admission refusal shape or source context differs")
        prior_authorities = authorities[:-1]
        if not prior_authorities:
            raise OrchestrationError("admission refusal lacks a prior resource authority")
        previous = _runtime_state_from_authority_record(prior_authorities[-1])
        prior_manifest = safe_json_loads(_canonical_bytes(manifest))
        prior_manifest["artifacts"].pop(RESOURCE_RUNTIME_ADMISSION_REFUSAL)
        prior_manifest.update(
            resource_runtime_artifact=prior_authorities[-1]["logical_type"],
            resource_runtime_state=previous.to_dict(),
            event_count=payload["source_event_count"],
            ledger_head_hash=payload["source_ledger_head_hash"],
            updated_at=payload["source_manifest_updated_at"],
        )
        if (_sha256(_canonical_bytes(prior_manifest)) != payload["source_manifest_sha256"]
                or payload["prior_authority_sha256"] != _sha256(_canonical_bytes(prior_authorities[-1]))
                or payload["source_registry_identities"] != sorted(
                    [[r.sha256, r.record_hash] for r in population.records if r != record])):
            raise OrchestrationError("admission source population or manifest was substituted")
        config, prior = self._admission_sources(
            prior_manifest, registry, prior_authorities, snapshot.events[:-1]
        )
        try:
            if (_canonical_bytes(payload["resource_config"]) != _canonical_bytes(config.to_dict())
                    or _canonical_bytes(payload["observation"]["request"])
                    != _canonical_bytes(self._admission_request(prior_manifest))):
                raise OrchestrationError("admission request or frozen policy differs")
            decision, runtime = _replay_resource_admission(config, prior, payload["observation"])
        except (ValueError, TypeError, KeyError) as exc:
            raise OrchestrationError("admission decision cannot be replayed") from exc
        parents = (
            prior_authorities[-1]["state_sha256"],
            prior_manifest["artifacts"]["frozen_source_inventory"]["sha256"],
            prior_manifest["artifacts"]["frozen_configuration_inventory"]["sha256"],
        )
        expected_record = self._admission_record(registry, payload, parents, manifest["created_at"])
        mirror = (Path("runs") / run_id / "artifacts" / manifest["current_state"].lower()
                  / f"{RESOURCE_RUNTIME_ADMISSION_REFUSAL}-{record.sha256[:20]}.json")
        expected_binding = {
            "logical_type": record.logical_type, "path": mirror.as_posix(),
            "sha256": record.sha256, "size": record.size, "schema_version": record.schema_version,
            "mime_type": record.mime_type, "origin": record.origin,
            "creator_role": record.creator_role.value, "creation_command": list(record.creation_command),
            "parent_artifacts": list(record.parent_artifacts), "validation_result": "PASS",
            "frozen": True, "registry_path": record.path,
            "registry_metadata_path": record.metadata_path, "registry_record_hash": record.record_hash,
        }
        if (record != expected_record or slot["state"] != payload
                or slot["state_sha256"] != record.sha256
                or registry.get_bytes(record.sha256) != _canonical_bytes(payload)
                or manifest.get("resource_runtime_state") != runtime.to_dict()
                or manifest.get("resource_runtime_artifact") != RESOURCE_RUNTIME_ADMISSION_REFUSAL
                or manifest["artifacts"][RESOURCE_RUNTIME_ADMISSION_REFUSAL] != expected_binding
                or read_confined_bytes(self.root, mirror, reject_hardlinks=True,
                                       max_bytes=1024 * 1024) != _canonical_bytes(payload)
                or event != self._admission_event(prior_manifest, payload, record, slot, registry)
                or snapshot.head_hash != manifest.get("ledger_head_hash")
                or snapshot.event_count != manifest.get("event_count")):
            raise OrchestrationError("admission commitment identity differs")
        self._validate_resource_authority_ledger(authorities, snapshot.events)
        _validate_monotonic_runtime_states((prior, runtime))
        # Exact local and external checkpoints are required; absence is never repaired.
        artifact_hashes = {k: v["sha256"] for k, v in sorted(manifest["artifacts"].items())}
        record_hashes = {k: v["registry_record_hash"] for k, v in sorted(manifest["artifacts"].items())}
        common = {
            "schema_version": SCHEMA_VERSION, "run_id": run_id, "state": manifest["current_state"],
            "artifact_hashes": artifact_hashes, "artifact_record_hashes": record_hashes,
            "resource_runtime_artifact": RESOURCE_RUNTIME_ADMISSION_REFUSAL,
            "ledger_head_hash": event.event_hash,
        }
        local = _read_json(self.root / "runs" / run_id / "checkpoint.json")
        if local != {**common, "terminal_state": None, "event_count": snapshot.event_count,
                     "resumable": False}:
            raise OrchestrationError("admission local checkpoint is incomplete or substituted")
        checkpoint_id = f"{event.event_id}-{event.event_hash[:12]}"
        external = _read_json(self.root / ".scientist-one-build/checkpoints" / run_id
                              / (checkpoint_id + ".json"))
        if (set(external) != set(common) | {"event_id", "checkpoint_id", "created_at", "checkpoint_hash"}
                or any(external.get(k) != v for k, v in common.items())
                or external["event_id"] != event.event_id or external["checkpoint_id"] != checkpoint_id
                or external["checkpoint_hash"] != _sha256(canonical_json_bytes(
                    {k: v for k, v in external.items() if k != "checkpoint_hash"}))):
            raise OrchestrationError("admission external checkpoint is incomplete or substituted")
        self._assert_no_newer_external_checkpoint(manifest)
        checkpoint_paths = tuple((self.root / ".scientist-one-build/checkpoints" / run_id).glob("*.json"))
        if sum(_read_json(path).get("event_id") == event.event_id for path in checkpoint_paths) != 1:
            raise OrchestrationError("admission checkpoint slot is duplicated")
        return payload

    def _admission_block_status(self, manifest, payload):
        return {
            "status": "RESOURCE_ADMISSION_BLOCKED", "run_id": manifest["run_id"],
            "current_state": manifest["current_state"], "terminal_state": None,
            "outcome": "RESOURCE_ADMISSION_BLOCKED", "mode": manifest.get("mode"),
            "artifact_count": len(manifest["artifacts"]), "event_count": manifest["event_count"],
            "resumable": False, "safe_resume_command": None,
            "operational_blocker": {
                "artifact_sha256": manifest["artifacts"][RESOURCE_RUNTIME_ADMISSION_REFUSAL]["sha256"],
                "action": payload["observation"]["decision"]["action"],
                "reasons": payload["observation"]["decision"]["reasons"],
                "scientific_evidence": False, "automatic_retry": False,
            },
        }

    def _commit_admission_refusal(self, manifest, controller, error, request):
        if (type(error) is not _ResourceAdmissionRefusal or error.controller is not controller
                or error.decision.allowed or not error.decision.checkpoint_required
                or error.observation_json is None):
            raise OrchestrationError("refusal did not originate in this admission")
        if self._resource_admission_refusal(manifest) is not None:
            raise _ResourceAdmissionBlocked("resource admission is already durably blocked")
        run_id = str(manifest["run_id"])
        registry = self._registry(run_id)
        ledger = EventLedger(self.root, Path("runs") / run_id / "events.jsonl")
        before_registry, before_ledger = _locked_resource_registry_ledger_snapshot(registry, ledger, run_id)
        authorities = self._resource_authority_records(run_id)
        config, prior = self._admission_sources(manifest, registry, authorities, before_ledger.events)
        observation = safe_json_loads(error.observation_json)
        if (_canonical_bytes(request) != _canonical_bytes(self._admission_request(manifest))
                or observation["request"] != request
                or _canonical_bytes(observation["decision"]) != _canonical_bytes(asdict(error.decision))):
            raise OrchestrationError("actual admission request is not the ordinary callsite")
        try:
            _decision, runtime = _replay_resource_admission(config, prior, observation)
        except (ValueError, TypeError, KeyError) as exc:
            raise OrchestrationError("actual refusal observation does not bind prior accounting") from exc
        payload = {
            "schema_version": _RESOURCE_ADMISSION_SCHEMA, "kind": "RESOURCE_ADMISSION_REFUSAL",
            "run_id": run_id, "state": manifest["current_state"], "resource_config": config.to_dict(),
            "observation": observation,
            "prior_authority_sha256": _sha256(_canonical_bytes(authorities[-1])),
            "source_registry_identities": sorted([[r.sha256, r.record_hash] for r in before_registry.records]),
            "source_event_count": before_ledger.event_count,
            "source_ledger_head_hash": before_ledger.head_hash,
            "source_manifest_sha256": _sha256(_canonical_bytes(manifest)),
            "source_manifest_updated_at": manifest["updated_at"],
            "creation_command": list(self.command_context), "recorded_at": _utc_now(),
            "authority_scope": "OPERATIONAL_STICKY_BLOCK", "scientific_evidence": False,
        }
        if not _supported_builtin_resource_command(self.command_context, run_id=run_id):
            raise OrchestrationError("refusal producer command is not built-in")
        parents = (authorities[-1]["state_sha256"],
                   manifest["artifacts"]["frozen_source_inventory"]["sha256"],
                   manifest["artifacts"]["frozen_configuration_inventory"]["sha256"])
        record = self._admission_record(registry, payload, parents, manifest["created_at"])
        authority = {
            "schema_version": SCHEMA_VERSION, "kind": "RESOURCE_RUNTIME_AUTHORITY", "run_id": run_id,
            "sequence": len(authorities), "logical_type": RESOURCE_RUNTIME_ADMISSION_REFUSAL,
            "state_sha256": record.sha256, "state": payload,
            "prior_authority_sha256": payload["prior_authority_sha256"],
        }
        event = self._admission_event(manifest, payload, record, authority, registry)
        ledger_raw = read_confined_bytes(
            self.root, Path("runs") / run_id / "events.jsonl",
            reject_hardlinks=True, max_bytes=MAX_LEDGER_BYTES,
        )
        if ledger_raw is None:
            raise OrchestrationError("admission ledger disappeared")
        prospective_raw = ledger_raw + _canonical_bytes(event.to_dict())
        prospective = ledger._validate_bytes(prospective_raw)
        checkpoint_projection = {
            "artifact_hashes": {k: v["sha256"] for k, v in manifest["artifacts"].items()},
            "artifact_record_hashes": {k: v["registry_record_hash"] for k, v in manifest["artifacts"].items()},
        }
        checkpoint_paths = tuple(
            (self.root / ".scientist-one-build/checkpoints" / run_id).glob("*.json")
        )
        if (len(authorities) >= 16 or before_registry.count + 1 > MAX_REGISTRY_RECORDS
                or before_ledger.event_count + 1 > MAX_LEDGER_EVENTS
                or len(prospective_raw) > MAX_LEDGER_BYTES
                or len(_canonical_bytes(authority)) > 1024 * 1024
                or len(_canonical_bytes(checkpoint_projection)) + 4096 > 8 * 1024 * 1024
                or len(checkpoint_paths) >= 256
                or (len(_canonical_bytes(manifest)) + len(_canonical_bytes(record.to_dict()))
                    + len(_canonical_bytes(runtime.to_dict())) + 8192 > 16 * 1024 * 1024)
                or not prospective.valid or prospective.events != (*before_ledger.events, event)):
            raise OrchestrationError("admission publication capacity or prospective binding is invalid")
        if (registry.verify_all(raise_on_error=True) != before_registry
                or ledger.assert_valid() != before_ledger
                or self._resource_authority_records(run_id) != authorities):
            raise OrchestrationError("admission sources changed before publication")
        if self._persist_resource_authority(manifest, RESOURCE_RUNTIME_ADMISSION_REFUSAL, payload) != authority:
            raise OrchestrationError("admission external publication differs")
        binding = self._artifact(manifest, RESOURCE_RUNTIME_ADMISSION_REFUSAL, payload,
                                 creator=Role.ORCHESTRATOR.value, parents=parents)
        if binding["registry_record_hash"] != record.record_hash:
            raise OrchestrationError("admission registry publication differs")
        ledger.append(event)
        manifest.update(resource_runtime_artifact=RESOURCE_RUNTIME_ADMISSION_REFUSAL,
                        resource_runtime_state=runtime.to_dict(),
                        event_count=prospective.event_count, ledger_head_hash=event.event_hash)
        self._checkpoint(manifest)
        self._resource_admission_refusal(manifest)
        raise _ResourceAdmissionBlocked("source-owned resource admission durably blocked")

    def _run_with_resources(
        self,
        manifest: dict[str, Any],
        *,
        experiment_id: str,
        validity_stage: str,
        validity_units: int,
        operation: Callable[[], Any] | None = None,
        charged_operation: Callable[[_ChargedResourceAuthority], Any]
        | None = None,
    ) -> Any:
        if (operation is None) == (charged_operation is None):
            raise OrchestrationError(
                "resource transaction requires exactly one operation"
            )
        if getattr(
            self._command_guard_state, "resource_transaction_active", False
        ) is True:
            raise OrchestrationError("nested resource transactions are prohibited")

        def execute_locked() -> Any:
            run_id = manifest.get("run_id")
            if not isinstance(run_id, str) or not RUN_ID_PATTERN.fullmatch(run_id):
                raise OrchestrationError(
                    "resource transaction requires a validated run ID"
                )
            fresh = self.load_manifest(run_id)
            self._assert_no_newer_external_checkpoint(fresh)
            if self._pilot_operation_disposition(fresh) is not None:
                raise OrchestrationError("pilot operation is durably blocked or unresolved")
            if self._resource_admission_refusal(fresh) is not None:
                raise _ResourceAdmissionBlocked("resource admission is durably blocked")
            if self._pilot_evaluation_context(fresh) is not None:
                raise OrchestrationError("completed pilot requires evaluator-only continuation")
            if _canonical_bytes(fresh) != _canonical_bytes(manifest):
                raise OrchestrationError(
                    "resource transaction caller projection is stale"
                )
            # Closures used by the bounded work stages intentionally retain
            # this dictionary object.  Refresh it in place so the transaction
            # and its operation share the just-reloaded canonical projection.
            manifest.clear()
            manifest.update(fresh)
            return self._run_with_resources_locked(
                manifest,
                experiment_id=experiment_id,
                validity_stage=validity_stage,
                validity_units=validity_units,
                operation=operation,
                charged_operation=charged_operation,
            )

        self._command_guard_state.resource_transaction_active = True
        try:
            if self._command_guard_depth():
                self._assert_project_root_identity()
                return execute_locked()
            with self._command_root_guard():
                return execute_locked()
        finally:
            self._command_guard_state.resource_transaction_active = False

    def _run_with_resources_locked(
        self,
        manifest: dict[str, Any],
        *,
        experiment_id: str,
        validity_stage: str,
        validity_units: int,
        operation: Callable[[], Any] | None,
        charged_operation: Callable[[_ChargedResourceAuthority], Any]
        | None,
    ) -> Any:
        controller = self._resource_controller(manifest)
        try:
            lease = controller.acquire(
                experiment_id,
                cpu_workers=1,
                gpu_jobs=0,
                validity_stage=validity_stage,
                validity_units=validity_units,
            )
        except ResourceLimitError as exc:
            if (type(exc) is _ResourceAdmissionRefusal
                    and {"WORK_STALLED", "REPEATED_WORKER_CRASHES"}.intersection(exc.decision.reasons)):
                self._commit_admission_refusal(manifest, controller, exc, {
                    "experiment_id": experiment_id, "cpu_workers": 1, "gpu_jobs": 0,
                    "estimated_artifact_bytes": 0, "validity_stage": validity_stage,
                    "validity_units": validity_units,
                })
            raise OrchestrationError(f"resource or validity admission failed: {exc}") from exc
        try:
            with lease:
                # The charge is atomic with admission. Persist it before any
                # experimental code can run so a crash cannot replenish it.
                manifest["resource_runtime_state"] = controller.export_state().to_dict()
                prior_name = manifest.get("resource_runtime_artifact")
                parents = (
                    (manifest["artifacts"][prior_name]["sha256"],)
                    if isinstance(prior_name, str) and prior_name in manifest["artifacts"]
                    else ()
                )
                charge_name = f"resource_runtime_{validity_stage.lower()}_charge"
                self._persist_resource_authority(
                    manifest, charge_name, manifest["resource_runtime_state"]
                )
                charge_record = self._artifact(
                    manifest,
                    charge_name,
                    manifest["resource_runtime_state"],
                    creator=Role.ORCHESTRATOR.value,
                    parents=parents,
                )
                manifest["resource_runtime_artifact"] = charge_name
                charge_event_id = self._append_event(
                    manifest,
                    str(manifest["current_state"]),
                    str(manifest["current_state"]),
                    f"atomic {validity_stage} validity charge persisted before execution",
                    (charge_name,),
                    (),
                    event_type="CHECKPOINT",
                )
                self._save_manifest(manifest)
                if charged_operation is not None:
                    if controller.validity_budget is None:
                        raise OrchestrationError(
                            "charged operation lacks a live validity budget"
                        )
                    result = charged_operation(
                        _ChargedResourceAuthority(
                            RegisteredArtifactSelector(
                                charge_record["sha256"],
                                charge_record["registry_record_hash"],
                            ),
                            charge_event_id,
                            controller.validity_budget.snapshot(),
                            validity_units,
                        )
                    )
                else:
                    assert operation is not None
                    result = operation()
        except ResourceLimitError as exc:
            raise OrchestrationError(f"resource or validity admission failed: {exc}") from exc
        controller.record_progress()
        manifest["resource_runtime_state"] = controller.export_state().to_dict()
        prior_name = str(manifest["resource_runtime_artifact"])
        completion_name = f"resource_runtime_{validity_stage.lower()}_completion"
        self._persist_resource_authority(
            manifest, completion_name, manifest["resource_runtime_state"]
        )
        self._artifact(
            manifest,
            completion_name,
            manifest["resource_runtime_state"],
            creator=Role.ORCHESTRATOR.value,
            parents=(manifest["artifacts"][prior_name]["sha256"],),
        )
        manifest["resource_runtime_artifact"] = completion_name
        self._append_event(
            manifest,
            str(manifest["current_state"]),
            str(manifest["current_state"]),
            f"{validity_stage} resource state persisted after execution",
            (completion_name,),
            (),
            event_type="CHECKPOINT",
        )
        self._save_manifest(manifest)
        return result

    def _recovery_report(self, manifest: Mapping[str, Any]) -> Any:
        custody = None
        custody_record = manifest.get("artifacts", {}).get("custody_record")
        if isinstance(custody_record, dict):
            custody = self._json_artifact_payload(manifest, "custody_record")
            if not self._validate_live_custody(manifest):
                custody = dict(custody)
                custody["confirmatory_claims_valid"] = False
                custody["violation_reasons"] = [
                    "durable custody journal is corrupt, advanced, or invalid"
                ]
        return RecoveryManager(
            self.root,
            ledger_validator=lambda path: self._foundation_ledger_validation(path),
        ).recover(
            ledger_path=(self._run_dir(str(manifest["run_id"])) / "events.jsonl").relative_to(self.root),
            artifact_registry=self._registry(str(manifest["run_id"])),
            checkpoint_dir=Path(".scientist-one-build/checkpoints") / str(manifest["run_id"]),
            expected_run_id=str(manifest["run_id"]),
            custody_record=custody,
            repair_truncated_tail=True,
        )

    def _validate_live_custody(self, manifest: Mapping[str, Any]) -> bool:
        """Reopen the durable journal; frozen snapshots never authorize alone."""

        if "custody_record" not in manifest.get("artifacts", {}):
            try:
                unexpected = read_confined_bytes(
                    self.root,
                    _custody_journal_path(str(manifest["run_id"])),
                    reject_hardlinks=True,
                    max_bytes=32 * 1024 * 1024,
                    missing_ok=True,
                )
            except PathSecurityError:
                return False
            return unexpected is None
        return self._validate_live_custody_mode(manifest, scientific=True)

    def _validate_live_architecture_control(
        self,
        manifest: Mapping[str, Any],
    ) -> bool:
        """Reopen and verify the explicit non-scientific simulated boundary."""

        if "custody_record" not in manifest.get("artifacts", {}):
            return False
        return self._validate_live_custody_mode(manifest, scientific=False)

    def _validate_live_custody_mode(
        self,
        manifest: Mapping[str, Any],
        *,
        scientific: bool,
    ) -> bool:
        try:
            snapshot = self._json_artifact_payload(manifest, "custody_record")
            raw_path = snapshot.get("journal_path")
            if (
                not isinstance(raw_path, str)
                or Path(raw_path).is_absolute()
                or ".." in Path(raw_path).parts
            ):
                return False
            expected_path = _custody_journal_path(str(manifest["run_id"]))
            if Path(raw_path) != expected_path:
                return False
            custody = SimulatedHoldoutCustody(
                (Role.EXPERIMENT_RUNNER.value,),
                journal_root=self.root,
                journal_path=expected_path,
            )
            expected_head = snapshot.get("journal_head_hash")
            expected_identity = snapshot.get("journal_identity_sha256")
            if not isinstance(expected_head, str) or not isinstance(
                expected_identity, str
            ):
                return False
            with custody.admission_guard(
                expected_journal_head_hash=expected_head,
                expected_journal_identity_sha256=expected_identity,
            ) as live:
                head = live.journal_head_hash
                status = live.status
                journal_sha256 = live.journal_sha256
                journal_size = live.journal_size
                journal_identity = live.journal_identity_sha256
                seal = live.seal
                access_records = _custody_access_records(live.journal_bytes)
                release_event = asdict(status.release_event) if status.release_event else None
            protocol_payload = self._json_artifact_payload(
                manifest, "frozen_protocol"
            )
            typed_protocol = protocol_payload.get("protocol")
            if not isinstance(typed_protocol, Mapping):
                return False
            scientific_status = (
                not status.invalidated
                and status.confirmatory_claims_valid
                and snapshot.get("confirmatory_claims_valid") is True
            )
            architecture_control_status = (
                status.invalidated
                and not status.confirmatory_claims_valid
                and snapshot.get("confirmatory_claims_valid") is False
                and snapshot.get("evidence_class") == "ARCHITECTURE_CONTROL"
                and snapshot.get("execution_kind")
                == "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
                and snapshot.get("scientific_evidence") is False
            )
            return (
                status.durable_journal
                and status.sealed
                and status.revealed
                and (
                    scientific_status
                    if scientific
                    else architecture_control_status
                )
                and status.authorized_access_count == 1
                and head == snapshot.get("journal_head_hash")
                and status.journal_head_hash == snapshot.get("journal_head_hash")
                and journal_sha256 == snapshot.get("journal_sha256")
                and journal_size == snapshot.get("journal_size")
                and journal_identity == snapshot.get("journal_identity_sha256")
                and snapshot.get("authorized_access_count") == 1
                and snapshot.get("custody_independence") == live.custody_label
                and snapshot.get("holdout_identity_hash")
                == seal.holdout_identity_hash
                and snapshot.get("split_manifest_hash") == seal.split_manifest_hash
                and snapshot.get("protocol_hash") == seal.protocol_hash
                and snapshot.get("code_hash") == seal.code_hash
                and snapshot.get("configuration_hash") == seal.configuration_hash
                and snapshot.get("pre_unblinding_interpretation_hash")
                == seal.pre_unblinding_interpretation_hash
                and snapshot.get("seal_hash") == seal.seal_hash
                and snapshot.get("sealing_time") == seal.sealed_at
                and snapshot.get("release_event") == release_event
                and snapshot.get("access_records") == access_records
                and snapshot.get("access_requester")
                == (status.release_event.requester if status.release_event else None)
                and snapshot.get("access_reason")
                == (status.release_event.reason if status.release_event else None)
                and snapshot.get("durable_journal") is True
                and snapshot.get("genuine_independence_claimed") is False
                and snapshot.get("study_id") == typed_protocol.get("study_id")
                and snapshot.get("study_version")
                == typed_protocol.get("study_version")
            )
        except Exception:
            return False

    def _validate_live_inventories(self, manifest: Mapping[str, Any]) -> bool:
        """Require the current workspace to equal the pre-confirm frozen inputs."""

        artifacts = manifest.get("artifacts", {})
        if not isinstance(artifacts, Mapping):
            return False
        if "frozen_source_inventory" not in artifacts:
            # Before CANDIDATE there is no frozen execution lineage yet.
            return True
        try:
            return (
                self._json_artifact_payload(manifest, "frozen_source_inventory")
                == _source_inventory(self.root)
                and self._json_artifact_payload(
                    manifest, "frozen_configuration_inventory"
                )
                == _configuration_inventory(self.root)
            )
        except Exception:
            return False

    def _foundation_ledger_validation(self, path: Path) -> Any:
        """Adapt the authoritative EventLedger result to recovery's shape."""

        from .recovery import LedgerValidationResult

        relative = path.relative_to(self.root)
        result = EventLedger(self.root, relative).validate()
        events = tuple(event.to_dict() for event in result.events)
        validation_error = result.error
        valid = result.valid
        legacy_run_path = (
            len(relative.parts) == 3
            and relative.parts[0] == "runs"
            and relative.parts[2] == "events.jsonl"
        )
        if valid and events and legacy_run_path:
            try:
                receipts = validate_legacy_transition_prefix(events)
                StateController(
                    initial_state=result.events[-1].requested_state_after,
                    artifact_registry=self._registry(result.events[0].run_id),
                    prior_receipts=receipts,
                )
            except Exception as exc:
                valid = False
                validation_error = f"INVALID_LEGACY_TRANSITION_AUTHORITY:{exc}"
        run_id = result.events[0].run_id if result.events else None
        return LedgerValidationResult(
            valid,
            events,
            result.head_hash,
            run_id,
            validation_error,
            result.error_line if result.error_line is not None else (len(events) if not valid else None),
            result.recoverable_truncated_tail,
            result.valid_prefix_bytes,
            0,
        )

    @_project_command
    def preflight(self) -> dict[str, Any]:
        profile = HardwareProfiler(self.root).collect()
        profile_payload = profile.to_dict()
        if "project_root" in profile_payload:
            profile_payload["project_root"] = "."
        # Preserve capability/version evidence without embedding executable
        # paths outside the project evidence boundary.
        toolchains = profile_payload.get("installed_toolchains", {})
        if isinstance(toolchains, dict):
            for logical_name, evidence in toolchains.items():
                if isinstance(evidence, dict) and isinstance(evidence.get("value"), str):
                    evidence["value"] = logical_name
                    evidence["path_recorded"] = False
        _atomic_json(self.root, "state/HARDWARE_PROFILE.json", profile_payload)
        selection = DeviceManager(preference="auto", dtype="float32").select()
        resource_config_bytes = read_confined_bytes(
            self.root,
            "configs/resource_limits.json",
            reject_hardlinks=True,
            max_bytes=1024 * 1024,
        )
        if resource_config_bytes is None:
            raise OrchestrationError("resource configuration disappeared")
        try:
            resource_config_payload = safe_json_loads(resource_config_bytes)
        except Exception as exc:
            raise OrchestrationError("resource configuration is malformed") from exc
        if not isinstance(resource_config_payload, Mapping):
            raise OrchestrationError("resource configuration must be an object")
        config = ResourceConfig.from_mapping(resource_config_payload)
        controller = ResourceController(config, self.root)
        decision = controller.evaluate()
        allowed = decision.allowed
        configuration_inventory = _configuration_inventory(self.root)
        resource_entry = next(
            (
                entry
                for entry in configuration_inventory["entries"]
                if entry.get("path") == "configs/resource_limits.json"
            ),
            None,
        )
        if (
            not isinstance(resource_entry, Mapping)
            or resource_entry.get("sha256") != _sha256(resource_config_bytes)
        ):
            raise OrchestrationError(
                "resource configuration differs from the configuration inventory"
            )
        result = {
            "schema_version": SCHEMA_VERSION,
            "status": "PASS" if allowed else decision.action.value,
            "offline": True,
            "network_probe_performed": False,
            "hardware_profile": profile_payload,
            "device_selection": selection.to_dict(),
            "resource_decision": asdict(decision),
            "resource_config_sha256": _sha256(resource_config_bytes),
            "resource_controller_config_sha256": controller.config_sha256,
            "configuration_inventory_aggregate_sha256": configuration_inventory[
                "aggregate_sha256"
            ],
            "external_integrations": "INTERFACES_AND_FIXTURES_ONLY",
        }
        _atomic_json(self.root, "state/PREFLIGHT_RESULT.json", result)
        return result

    @_project_command
    def calibrate(self) -> dict[str, Any]:
        report = assert_calibrated(run_calibration())
        result = report.to_dict()
        result["status"] = "PASS"
        result["external_integrations_used"] = []
        _atomic_json(self.root, "state/CALIBRATION_RESULT.json", result)
        return result

    @_project_command
    def start(
        self,
        brief: str | Path | None = None,
        *,
        mode: str | None = None,
        synthetic_scenario: str = "positive",
    ) -> dict[str, Any]:
        selected_mode = mode or ("brief" if brief is not None else "synthetic_demo")
        if selected_mode not in {"brief", "synthetic_demo"}:
            raise OrchestrationError("unsupported run mode")
        if synthetic_scenario not in {"positive", "null", "reversal", "unstable"}:
            raise OrchestrationError("unsupported bounded synthetic scenario")
        if selected_mode != "synthetic_demo" and synthetic_scenario != "positive":
            raise OrchestrationError("synthetic scenarios apply only to the local demo")
        run_id = f"run-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:10]}"
        self._run_dir(run_id, create=True)
        _secure_directory(
            self.root,
            Path(".scientist-one-build/resource-authority") / run_id,
            create=True,
        )
        manifest: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "kind": "SCIENTIST_ONE_RUN_MANIFEST",
            "run_id": run_id,
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
            "mode": selected_mode,
            "synthetic_scenario": synthetic_scenario,
            "package_kind": "DEMO_RESEARCH_PACKAGE" if selected_mode == "synthetic_demo" else "RESEARCH_RUN",
            "current_state": "CALIBRATE",
            "terminal_state": None,
            "outcome": "IN_PROGRESS",
            "novelty": "NOVELTY_UNVERIFIED",
            "external_integrations_used": [],
            "external_integrations_policy": "interfaces_and_local_fixtures_only",
            "code_fingerprint": "",
            "configuration_sha256": "",
            "python_executable_name": Path(sys.executable).name,
            "python_version": sys.version.split()[0],
            "fixture_identifiers": ["calibration_cases_v1", "synthetic_workflow_v1"] if selected_mode == "synthetic_demo" else ["local_research_brief"],
            "random_seeds": [20260812],
            "transition_contracts": {
                key: _contract_dict(value) for key, value in TRANSITION_CONTRACTS.items()
            },
            "artifacts": {},
            "evaluator_decisions": {},
            "r_checks": {f"R{index}": "MISSING" for index in range(8)},
            "reproduction": None,
            "package": None,
            "event_count": 0,
            "ledger_head_hash": None,
            "completed_transitions": [],
            "typed_transition_receipts": [],
        }
        manifest["resource_runtime_state"] = self._resource_controller(manifest).export_state().to_dict()
        source_inventory = _source_inventory(self.root)
        configuration_inventory = _configuration_inventory(self.root)
        _validate_loaded_project_modules(self.root, source_inventory)
        manifest["code_fingerprint"] = source_inventory["aggregate_sha256"]
        manifest["configuration_sha256"] = configuration_inventory["aggregate_sha256"]
        self._artifact(
            manifest,
            "frozen_source_inventory",
            source_inventory,
            creator=Role.ORCHESTRATOR.value,
        )
        self._artifact(
            manifest,
            "frozen_configuration_inventory",
            configuration_inventory,
            creator=Role.ORCHESTRATOR.value,
        )
        self._persist_resource_authority(
            manifest,
            "resource_runtime_initial",
            manifest["resource_runtime_state"],
        )
        self._artifact(
            manifest,
            "resource_runtime_initial",
            manifest["resource_runtime_state"],
            creator=Role.ORCHESTRATOR.value,
        )
        manifest["resource_runtime_artifact"] = "resource_runtime_initial"
        self._artifact(
            manifest,
            "run_intent",
            {
                "schema_version": SCHEMA_VERSION,
                "kind": "FROZEN_RUN_INTENT",
                "mode": selected_mode,
                "synthetic_scenario": synthetic_scenario,
                "package_kind": manifest["package_kind"],
            },
            creator=Role.ORCHESTRATOR.value,
            parents=(
                manifest["artifacts"]["frozen_source_inventory"]["sha256"],
                manifest["artifacts"]["frozen_configuration_inventory"]["sha256"],
            ),
        )
        if brief is not None:
            manifest["current_state"] = "CALIBRATE"
            self._artifact_from_file(manifest, "research_brief", Path(brief), creator=Role.PROBLEM_INVESTIGATOR.value, mime_type="text/markdown", max_bytes=1024 * 1024)
        self._append_event(manifest, "INITIALIZED", "CALIBRATE", "run initialized inside the offline project boundary", tuple(manifest["artifacts"]), ())
        self._checkpoint(manifest)
        return self.status(run_id)

    @_project_command
    def status(self, run_id: str | None = None) -> dict[str, Any]:
        if run_id is not None:
            operation = self._fixture_operation_receipt(run_id)
            if operation is not None:
                if self._manifest_name_present(run_id):
                    raise OrchestrationError(
                        "run contains ambiguous legacy and vNext authorities"
                    )
                return self._vnext_fixture_status(run_id, operation)
            manifest = self.load_manifest(run_id)
            self._assert_no_newer_external_checkpoint(manifest)
            pilot_disposition = self._pilot_operation_disposition(manifest)
            if pilot_disposition is not None:
                return pilot_disposition
            if manifest.get("terminal_state") is None:
                refusal = self._resource_admission_refusal(manifest)
                if refusal is not None:
                    return self._admission_block_status(manifest, refusal)
            pending = self._pilot_evaluation_context(manifest)
            if pending is not None:
                return self._pilot_evaluation_status(pending)
            recovery = self._recovery_report(manifest)
            if recovery.action.value in {
                "STOP_SECURITY",
                "STOP_SCIENTIFIC_INVALIDITY",
                "NEW_STUDY_REQUIRED",
            }:
                return {
                    "status": recovery.action.value,
                    "run_id": run_id,
                    "current_state": recovery.derived_state,
                    "terminal_state": manifest.get("terminal_state"),
                    "outcome": recovery.action.value,
                    "mode": manifest.get("mode"),
                    "artifact_count": len(manifest.get("artifacts", {})),
                    "event_count": recovery.ledger_event_count,
                    "resumable": False,
                    "recovery": recovery.to_dict(),
                }
            derived_state = recovery.derived_state
            derived_terminal = (
                derived_state if derived_state in TERMINAL_STATES else None
            )
            expected_outcome = (
                "COMPLETE_DEMO_ONLY"
                if derived_terminal == "READY_FOR_HUMAN_REVIEW"
                else derived_terminal or "IN_PROGRESS"
            )
            if (
                derived_state != manifest.get("current_state")
                or manifest.get("terminal_state") != derived_terminal
                or manifest.get("outcome") != expected_outcome
            ):
                raise OrchestrationError(
                    "mutable terminal projection is not ledger-derived"
                )
            if derived_terminal != "STOP_SECURITY":
                self._resource_controller(manifest)
            if derived_terminal is not None:
                if derived_terminal == "READY_FOR_HUMAN_REVIEW":
                    try:
                        package_run(self.root, run_id)
                    except Exception as exc:
                        raise OrchestrationError(
                            "final review packet or envelope is not verified"
                        ) from exc
            resumable = recovery.resumable and derived_terminal is None
            return {
                "status": "PASS",
                "run_id": run_id,
                "current_state": manifest["current_state"],
                "terminal_state": manifest.get("terminal_state"),
                "outcome": manifest["outcome"],
                "mode": manifest["mode"],
                "artifact_count": len(manifest["artifacts"]),
                "event_count": manifest["event_count"],
                "resumable": resumable,
                "safe_resume_command": (
                    [
                        "python3", "-I", "-S", "-B",
                        "scripts/scientist_one_cli.py", "resume", run_id,
                    ]
                    if resumable
                    else None
                ),
                "recovery": recovery.to_dict(),
            }
        runs_dir = _secure_directory(self.root, "runs")
        summaries = []
        for child in sorted(runs_dir.iterdir()):
            if child.is_symlink() or not child.is_dir() or not RUN_ID_PATTERN.fullmatch(child.name):
                continue
            manifest_path = child / "manifest.json"
            operation_path = child / "fixture-operation.json"
            if (
                manifest_path.exists()
                or manifest_path.is_symlink()
                or operation_path.exists()
                or operation_path.is_symlink()
            ):
                try:
                    summaries.append(self.status(child.name))
                except OrchestrationError as exc:
                    summaries.append(
                        {
                            "status": "ERROR",
                            "run_id": child.name,
                            "message": str(exc),
                        }
                    )
        return {"status": "PASS", "runs": summaries, "count": len(summaries)}

    @_project_command
    def research_os_fixture(
        self,
        run_id: str | None = None,
        *,
        restart_from_run_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute vNext only while holding the admitted project-root guard."""

        from .research_os import (
            _run_research_os_fixture_guarded,
            run_research_os_fixture,
        )

        if getattr(sys, "_scientist_one_isolated_launcher", False) is not True:
            if restart_from_run_id is not None:
                raise OrchestrationError(
                    "restart lineage is available only through guarded production dispatch"
                )
            return run_research_os_fixture(self.root, run_id=run_id)
        capability = self._mint_guarded_launch_capability(
            run_id,
            restart_from_run_id=restart_from_run_id,
        )
        return _run_research_os_fixture_guarded(
            self.root,
            run_id=run_id,
            restart_from_run_id=restart_from_run_id,
            capability=capability,
        )

    def _json_artifact_payload(self, manifest: Mapping[str, Any], name: str) -> dict[str, Any]:
        record = manifest["artifacts"].get(name)
        if not isinstance(record, dict):
            raise OrchestrationError(f"missing artifact: {name}")
        try:
            registry = self._registry(str(manifest["run_id"]))
            metadata = registry.get_metadata(str(record["sha256"]))
            data = registry.get_bytes(str(record["sha256"]))
            value = safe_json_loads(data)
        except Exception as exc:
            raise OrchestrationError(f"artifact is absent, corrupt, or unsafe: {name}") from exc
        if (
            not isinstance(value, dict)
            or metadata.logical_type != record.get("logical_type")
            or metadata.record_hash != record.get("registry_record_hash")
            or _sha256(data) != record.get("sha256")
        ):
            raise OrchestrationError(f"artifact registry binding mismatch: {name}")
        return value

    def _handler_calibrate(self, manifest: dict[str, Any]) -> None:
        receipt_path = self.root / "state" / "APP_SESSION_BOOTSTRAP.json"
        receipt = _read_json(receipt_path)
        receipt_bytes = read_confined_bytes(
            self.root,
            receipt_path.relative_to(self.root),
            reject_hardlinks=True,
            max_bytes=1024 * 1024,
        )
        if receipt_bytes is None:
            raise OrchestrationError("bootstrap receipt disappeared")
        bootstrap_evidence = {
            "schema_version": SCHEMA_VERSION,
            "kind": "CONFINED_BOOTSTRAP_RECEIPT_REFERENCE",
            "app_session_bootstrap": receipt.get("app_session_bootstrap"),
            "bootstrap_checks": receipt.get("bootstrap_checks"),
            "canonical_project_root": ".",
            "source_receipt_sha256": _sha256(receipt_bytes),
            "external_absolute_paths_recorded": False,
        }
        self._artifact(
            manifest,
            "bootstrap_receipt",
            bootstrap_evidence,
            creator=Role.ORCHESTRATOR.value,
        )
        self._artifact(manifest, "calibration_report", self.calibrate(), creator=Role.ORCHESTRATOR.value)
        self._evaluate(
            manifest,
            "E0:CALIBRATE",
            EvaluatorClass.E0,
            Role.ORCHESTRATOR,
            ("bootstrap_receipt", "calibration_report"),
            (RCheck.R0,),
        )

    def _queue_terminal(
        self,
        manifest: dict[str, Any],
        destination: str,
        reason: str,
        *,
        evidence: Mapping[str, Any] | None = None,
    ) -> None:
        if destination not in TERMINAL_STATES or destination == "READY_FOR_HUMAN_REVIEW":
            raise OrchestrationError("invalid queued terminal destination")
        manifest["pending_terminal"] = {
            "destination": destination,
            "reason": reason,
            "evidence": dict(evidence or {}),
        }

    def _transition_terminal(self, manifest: dict[str, Any]) -> None:
        """Materialize and execute one canonical evidence-bearing terminal edge."""

        pending = manifest.get("pending_terminal")
        if not isinstance(pending, dict):
            raise OrchestrationError("terminal transition lacks a typed pending decision")
        source_name = str(manifest["current_state"])
        destination_name = pending.get("destination")
        reason = pending.get("reason")
        if source_name not in MACRO_STATES or not isinstance(destination_name, str):
            raise OrchestrationError("terminal transition source or destination is invalid")
        if not isinstance(reason, str) or not reason.strip():
            raise OrchestrationError("terminal transition reason is required")
        source = MacroState(source_name)
        destination = TerminalState(destination_name)
        contract = next(
            (
                item
                for item in default_transition_contracts()
                if item.source is source and item.destination is destination
            ),
            None,
        )
        if contract is None:
            raise OrchestrationError(
                f"canonical terminal outcome is not allowed from {source_name}"
            )
        evidence = pending.get("evidence")
        if not isinstance(evidence, dict):
            raise OrchestrationError("terminal evidence must be an object")
        # A terminal report is the authoritative closure root for every
        # artifact already materialized by the interrupted stage.  Otherwise
        # a work-refusing handler could leave an unledgered orphan such as a
        # diagnostic preflight report.
        parents = tuple(
            manifest["artifacts"][name]["sha256"]
            for name in sorted(manifest["artifacts"])
            if name != "terminal_report"
        )
        self._artifact(
            manifest,
            "terminal_report",
            {
                "schema_version": SCHEMA_VERSION,
                "kind": "TYPED_TERMINAL_REPORT",
                "run_id": manifest["run_id"],
                "source_state": source_name,
                "terminal_state": destination_name,
                "reason": reason,
                "evidence": evidence,
                "honest_negative_or_inconclusive": destination
                in {TerminalState.NEGATIVE_RESULT, TerminalState.INCONCLUSIVE},
            },
            creator=Role.ORCHESTRATOR.value,
            parents=parents,
        )
        artifact_names = tuple(sorted(contract.required_artifact_types))
        evaluator_key_map: dict[EvaluatorClass, str] = {}
        for evaluator in sorted(contract.required_evaluators, key=lambda item: item.value):
            authority = (
                Role.ORCHESTRATOR
                if evaluator is EvaluatorClass.E0
                else Role.SCIENTIFIC_REVIEWER
            )
            producer = (
                None if evaluator is EvaluatorClass.E0 else Role.EXPERIMENT_RUNNER
            )
            key = _terminal_evaluation_key(source_name, destination_name, evaluator)
            evaluator_key_map[evaluator] = key
            self._evaluate(
                manifest,
                key,
                evaluator,
                authority,
                artifact_names,
                (),
                producer=producer,
            )
        evaluator_keys = tuple(
            evaluator_key_map[evaluator]
            for evaluator in sorted(contract.required_evaluators, key=lambda item: item.value)
        )
        receipt = self._typed_transition(
            manifest, contract, evaluator_key_map=evaluator_key_map
        )
        manifest["typed_transition_receipts"].append(receipt)
        self._append_event(
            manifest,
            source_name,
            destination_name,
            reason,
            artifact_names,
            evaluator_keys,
            event_type="SECURITY_STOP"
            if destination is TerminalState.STOP_SECURITY
            else "TRANSITION",
            metadata=(
                {
                    "resource_authority_chain": self._resource_authority_descriptors(
                        self._resource_authority_records(str(manifest["run_id"]))
                    )
                }
                if evidence.get("resource_authority")
                == "ROLLBACK_OR_STALE_PROJECTION"
                else None
            ),
        )
        manifest["completed_transitions"].append(
            f"{source_name}->{destination_name}"
        )
        manifest["current_state"] = destination_name
        manifest["terminal_state"] = destination_name
        manifest["outcome"] = destination_name
        manifest.pop("pending_terminal", None)
        self._checkpoint(manifest)

    def _handler_charter(self, manifest: dict[str, Any]) -> None:
        if manifest["mode"] != "synthetic_demo":
            self._queue_terminal(
                manifest,
                "BLOCKED_EXTERNAL",
                "a non-synthetic run requires locally supplied external evidence and providers",
                evidence={"mode": manifest["mode"], "network_used": False},
            )
            return
        payload = {
            "kind": "SYNTHETIC_RESEARCH_CHARTER",
            "target_problem": "validate scientific-controller behavior on known-answer synthetic cases",
            "unit_of_analysis": "synthetic independent unit",
            "inputs": "frozen local JSON fixtures",
            "outputs": "typed decisions and audit evidence",
            "comparison": "observed evaluator decision versus frozen known answer",
            "estimand": "difference of group arithmetic means for the planted-signal primary fixture",
            "plausible_contribution": "architecture-control demonstration only",
            "falsifiable_hypothesis": "all mandatory traps are correctly distinguished and the primary effect reproduces exactly",
            "failure_conditions": ["any mandatory calibration miss", "holdout misuse", "unsupported claim", "reproduction discrepancy"],
            "scope_exclusions": ["external novelty", "real-world generalization", "publication readiness"],
            "novelty": "NOVELTY_UNVERIFIED",
        }
        self._artifact(manifest, "research_charter", payload, creator=Role.PROBLEM_INVESTIGATOR.value, parents=(manifest["artifacts"]["calibration_report"]["sha256"],))
        self._evaluate(manifest, "E0:CHARTER", EvaluatorClass.E0, Role.ORCHESTRATOR, ("research_charter",), (RCheck.R1,), producer=Role.PROBLEM_INVESTIGATOR)

    def _handler_ground(self, manifest: dict[str, Any]) -> None:
        payload = {
            "kind": "LOCAL_EVIDENCE_INVENTORY",
            "sources": [
                {"id": "calibration_cases_v1", "type": "synthetic_fixture", "external": False},
                {"id": "synthetic_workflow_v1", "type": "synthetic_fixture", "external": False},
            ],
            "literature_corpus_available": False,
            "citations": [],
            "novelty": "NOVELTY_UNVERIFIED",
            "prompt_instructions_in_artifacts": "treated_as_inert_untrusted_data",
        }
        self._artifact(manifest, "evidence_inventory", payload, creator=Role.EVIDENCE_CURATOR.value)
        self._evaluate(manifest, "E0:GROUND", EvaluatorClass.E0, Role.ORCHESTRATOR, ("evidence_inventory",), (RCheck.R0, RCheck.R1), producer=Role.EVIDENCE_CURATOR)

    def _handler_protocol(self, manifest: dict[str, Any]) -> None:
        frozen_study = _synthetic_study(str(manifest["run_id"]))
        typed_protocol = frozen_study.protocol
        validation = validate_protocol(typed_protocol)
        protocol = {
            "kind": "FROZEN_SYNTHETIC_PROTOCOL",
            "frozen": True,
            "protocol": typed_protocol.canonical_dict,
            "protocol_sha256": frozen_study.protocol_hash,
            "baseline_equivalence": [asdict(item) for item in validation],
            "blind_patterns": ["positive", "null", "sign reversal", "high variance", "failed robustness", "baseline underperformance", "subgroup inconsistency", "leakage or protocol failure"],
            "reproduction_tolerance": 1e-12,
        }
        self._artifact(manifest, "frozen_protocol", protocol, creator=Role.PROTOCOL_DESIGNER.value)
        manifest["protocol_hash"] = frozen_study.protocol_hash
        self._evaluate(manifest, "E0:PROTOCOL", EvaluatorClass.E0, Role.ORCHESTRATOR, ("frozen_protocol",), (RCheck.R1,), producer=Role.PROTOCOL_DESIGNER)
        self._evaluate(manifest, "E2:PROTOCOL", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, ("frozen_protocol",), (RCheck.R1,), producer=Role.PROTOCOL_DESIGNER)

    def _handler_preflight(self, manifest: dict[str, Any]) -> None:
        payload = self.preflight()
        frozen_configuration = self._json_artifact_payload(
            manifest, "frozen_configuration_inventory"
        )
        resource_entry = next(
            (
                entry
                for entry in frozen_configuration.get("entries", ())
                if isinstance(entry, Mapping)
                and entry.get("path") == "configs/resource_limits.json"
            ),
            None,
        )
        if (
            payload.get("configuration_inventory_aggregate_sha256")
            != manifest.get("configuration_sha256")
            or not isinstance(resource_entry, Mapping)
            or payload.get("resource_config_sha256") != resource_entry.get("sha256")
        ):
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "preflight resource configuration differs from frozen configuration",
                evidence={"configuration_binding": "FAIL"},
            )
            return
        self._artifact(
            manifest,
            "preflight_report",
            payload,
            creator=Role.ORCHESTRATOR.value,
        )
        if payload["status"] != "PASS":
            self._queue_terminal(
                manifest,
                "STOP_BUDGET",
                "preflight resource controller refused new work",
                evidence={
                    "resource_action": payload["status"],
                    "resource_decision": payload["resource_decision"],
                    "preflight_report_sha256": manifest["artifacts"]["preflight_report"]["sha256"],
                },
            )
            return
        self._evaluate(manifest, "E0:PREFLIGHT", EvaluatorClass.E0, Role.ORCHESTRATOR, ("preflight_report",), (RCheck.R0, RCheck.R2))

    def _handler_ideate(self, manifest: dict[str, Any]) -> None:
        payload = {"kind": "FROZEN_HYPOTHESIS_SET", "primary": "synthetic planted effect equals 1.0", "negative_control": "true-null effect equals 0.0", "reversal_trap": "development and confirmatory signs differ", "selection_after_results": False}
        self._artifact(manifest, "hypothesis_set", payload, creator=Role.HYPOTHESIS_DESIGNER.value)
        self._evaluate(manifest, "E0:IDEATE", EvaluatorClass.E0, Role.ORCHESTRATOR, ("hypothesis_set",), (RCheck.R1,), producer=Role.HYPOTHESIS_DESIGNER)

    def _handler_discover(self, manifest: dict[str, Any]) -> None:
        report = run_synthetic_workflow_benchmark().to_dict()
        if not report["passed"]:
            self._queue_terminal(
                manifest,
                "STOP_SCIENTIFIC_INVALIDITY",
                "mandatory synthetic workflow benchmark failed",
                evidence={"benchmark": report},
            )
            return
        self._artifact(manifest, "workflow_benchmark", report, creator=Role.EXPERIMENT_RUNNER.value)
        self._evaluate(manifest, "E0:DISCOVER", EvaluatorClass.E0, Role.ORCHESTRATOR, ("workflow_benchmark",), (RCheck.R2, RCheck.R3, RCheck.R4, RCheck.R5), producer=Role.EXPERIMENT_RUNNER)
        self._evaluate(manifest, "E2:DISCOVER", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, ("workflow_benchmark",), (RCheck.R2, RCheck.R3, RCheck.R4, RCheck.R5), producer=Role.EXPERIMENT_RUNNER)

    @staticmethod
    def _pilot_publications(manifest):
        benchmark_hash = manifest["artifacts"]["workflow_benchmark"]["sha256"]
        first = ("pilot_report", {"kind": "DEVELOPMENT_ONLY_PILOT", "passed": True, "confirmatory_evidence": False, "runtime_class": "bounded_small", "validity_reserve_consumed": 0.0}, Role.EXPERIMENT_RUNNER.value, (benchmark_hash,))
        source_record = manifest["artifacts"]["frozen_source_inventory"]
        configuration_record = manifest["artifacts"][
            "frozen_configuration_inventory"
        ]
        inventory_parents = (
            source_record["sha256"],
            configuration_record["sha256"],
        )
        second = ("midrun_review", {"kind": "FROZEN_MIDRUN_REVIEW", "passed": True, "drift": False, "leakage": False, "baseline_equivalent": True, "validity_reserve_intact": True, "code_fingerprint": manifest["code_fingerprint"], "configuration_sha256": manifest["configuration_sha256"], "source_inventory_sha256": source_record["sha256"], "configuration_inventory_sha256": configuration_record["sha256"]}, Role.SCIENTIFIC_REVIEWER.value, inventory_parents)
        third = ("blind_interpretation", {"kind": "FROZEN_BLIND_INTERPRETATION", "frozen_before_reveal": True, "source_inventory_sha256": source_record["sha256"], "configuration_inventory_sha256": configuration_record["sha256"], "patterns": {"positive": "bounded positive synthetic claim", "null": "NEGATIVE_RESULT", "sign_reversal": "INCONCLUSIVE", "high_variance": "INCONCLUSIVE", "failed_robustness": "INCONCLUSIVE", "baseline_underperformance": "INCONCLUSIVE", "subgroup_inconsistency": "INCONCLUSIVE", "leakage_or_protocol_failure": "STOP_SCIENTIFIC_INVALIDITY"}}, Role.STATISTICIAN.value, inventory_parents)

        return first, second, third

    @_project_command
    def _handler_candidate(self, manifest: dict[str, Any]) -> None:
        if not self._validate_live_inventories(manifest):
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "source or configuration drifted before candidate execution",
                evidence={
                    "frozen_source_inventory": manifest["artifacts"][
                        "frozen_source_inventory"
                    ]["sha256"],
                    "frozen_configuration_inventory": manifest["artifacts"][
                        "frozen_configuration_inventory"
                    ]["sha256"],
                },
            )
            return

        observed = None

        def pilot() -> None:
            nonlocal observed
            # Capturing is deliberately outside the body's exception witness.
            base = self._capture_pilot_base(manifest)
            try:
                for name, payload, creator, parents in self._pilot_publications(base["manifest"]):
                    self._artifact(manifest, name, payload, creator=creator, parents=parents)
            except Exception as error:
                observed = (error, base)
                raise

        try:
            self._run_with_resources(
                manifest,
                experiment_id=f"{manifest['run_id']}:pilot",
                validity_stage="PILOT",
                validity_units=2,
                operation=pilot,
            )
        except Exception as propagated:
            if observed is not None:
                original, base = observed
                direct_conversion = (
                    isinstance(original, ResourceLimitError)
                    and type(propagated) is OrchestrationError
                    and propagated.__cause__ is original
                )
                if propagated is original or direct_conversion:
                    diagnostic = ("RESOURCE_LIMIT_ERROR" if isinstance(original, ResourceLimitError)
                                  else "ORDINARY_EXCEPTION")
                    try:
                        self._commit_pilot_failure(manifest, base, diagnostic)
                    except Exception as publication_error:
                        raise publication_error from propagated
            raise
        self._evaluate_candidate(manifest)

    def _evaluate_candidate(self, manifest):
        """The original deterministic evaluator tail, shared without reexecution."""
        names = ("pilot_report", "midrun_review", "blind_interpretation")
        self._evaluate(manifest, "E0:CANDIDATE", EvaluatorClass.E0, Role.ORCHESTRATOR, names, (RCheck.R2, RCheck.R3, RCheck.R4, RCheck.R5), producer=Role.EXPERIMENT_RUNNER)
        self._evaluate(manifest, "E2:CANDIDATE", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, names, (RCheck.R1, RCheck.R4, RCheck.R5), producer=Role.EXPERIMENT_RUNNER)
        self._evaluate(manifest, "E3:CANDIDATE", EvaluatorClass.E3, Role.ADVERSARIAL_REVIEWER, names, (RCheck.R2, RCheck.R3, RCheck.R5), producer=Role.EXPERIMENT_RUNNER)

    def _handler_confirm(self, manifest: dict[str, Any]) -> None:
        frozen_source = self._json_artifact_payload(
            manifest, "frozen_source_inventory"
        )
        frozen_configuration = self._json_artifact_payload(
            manifest, "frozen_configuration_inventory"
        )
        observed_source = _source_inventory(self.root)
        observed_configuration = _configuration_inventory(self.root)
        if frozen_source != observed_source or frozen_configuration != observed_configuration:
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "frozen code or configuration drifted before confirmatory execution",
                evidence={
                    "expected_source_inventory": frozen_source.get(
                        "aggregate_sha256"
                    ),
                    "observed_source_inventory": observed_source.get(
                        "aggregate_sha256"
                    ),
                    "expected_configuration_inventory": frozen_configuration.get(
                        "aggregate_sha256"
                    ),
                    "observed_configuration_inventory": observed_configuration.get(
                        "aggregate_sha256"
                    ),
                },
            )
            return
        run_intent = self._json_artifact_payload(manifest, "run_intent")
        scenario = str(run_intent.get("synthetic_scenario", ""))
        if scenario != manifest.get("synthetic_scenario"):
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "mutable run scenario differs from frozen run intent",
                evidence={"frozen_scenario": scenario},
            )
            return
        fixtures = {
            "positive": {"control": [0.0, 1.0, 2.0, 3.0], "treatment": [1.0, 2.0, 3.0, 4.0]},
            "null": {"control": [0.0, 1.0, 2.0, 3.0], "treatment": [0.0, 1.0, 2.0, 3.0]},
            "reversal": {"control": [0.0, 1.0, 2.0, 3.0], "treatment": [-1.0, 0.0, 1.0, 2.0]},
            "unstable": {"control": [0.0, 1.0, 2.0, 3.0], "treatment": [-100.0, 102.0, -98.0, 104.0]},
        }
        fixture = fixtures.get(scenario)
        if fixture is None:
            raise OrchestrationError("unknown bounded synthetic outcome scenario")
        protocol_artifact_hash = manifest["artifacts"]["frozen_protocol"]["sha256"]
        protocol_hash = manifest["protocol_hash"]
        blind_hash = manifest["artifacts"]["blind_interpretation"]["sha256"]
        source_inventory_hash = manifest["artifacts"]["frozen_source_inventory"]["sha256"]
        configuration_inventory_hash = manifest["artifacts"]["frozen_configuration_inventory"]["sha256"]
        frozen_study = _synthetic_study(str(manifest["run_id"]))
        if frozen_study.protocol_hash != protocol_hash:
            raise OrchestrationError("typed study differs from the frozen protocol")
        split_id = "synthetic-confirmatory-v1"
        split_hash = _sha256(
            _canonical_bytes({"id": split_id, "role": "holdout"})
        )
        split_record = self._artifact(
            manifest,
            "frozen_confirmatory_split",
            {
                "schema_version": SCHEMA_VERSION,
                "kind": "FROZEN_CONFIRMATORY_SPLIT",
                "study_id": frozen_study.study_id,
                "study_version": frozen_study.version,
                "split_id": split_id,
                "role": "holdout",
                "split_manifest_hash": split_hash,
            },
            creator=Role.PROTOCOL_DESIGNER.value,
            parents=(protocol_artifact_hash,),
        )
        custody_journal = _custody_journal_path(str(manifest["run_id"]))
        custody_adapter = SimulatedHoldoutCustody(
            (Role.EXPERIMENT_RUNNER.value,),
            journal_root=self.root,
            journal_path=custody_journal,
        )
        fixture_bytes = _canonical_bytes(fixture)
        seal = custody_adapter.seal(
            fixture_bytes,
            split_manifest_hash=split_hash,
            protocol_hash=protocol_hash,
            code_hash=manifest["code_fingerprint"],
            configuration_hash=manifest["configuration_sha256"],
            pre_unblinding_interpretation_hash=blind_hash,
            sealed_at=manifest["created_at"],
        )
        with custody_adapter.admission_guard() as sealed_live:
            sealed_status = sealed_live.status
            sealed_journal_head = sealed_live.journal_head_hash
            sealed_journal_identity = sealed_live.journal_identity_sha256
        custody_verified_unaccessed = (
            sealed_status.sealed
            and not sealed_status.revealed
            and not sealed_status.invalidated
            and sealed_status.authorized_access_count == 0
            and sealed_status.durable_journal
            and isinstance(sealed_journal_head, str)
            and len(sealed_journal_head) == 64
        )
        if not custody_verified_unaccessed:
            raise OrchestrationError("durable custody cannot attest an untouched sealed holdout")
        receipt = self._artifact(
            manifest,
            "fresh_custody_receipt",
            {
                "schema_version": SCHEMA_VERSION,
                "study_id": frozen_study.study_id,
                "study_version": frozen_study.version,
                "seal": asdict(seal),
                "status": asdict(sealed_status),
                "journal_head_hash": sealed_journal_head,
                "journal_identity_sha256": sealed_journal_identity,
            },
            creator=Role.HOLDOUT_CUSTODIAN.value,
            parents=(
                protocol_artifact_hash,
                blind_hash,
                source_inventory_hash,
                configuration_inventory_hash,
                split_record["sha256"],
                manifest["artifacts"]["midrun_review"]["sha256"],
            ),
        )
        receipt_event_id = self._append_event(
            manifest,
            "CONFIRM",
            "CONFIRM",
            "durable sealed custody receipt frozen before confirmatory admission",
            ("fresh_custody_receipt",),
            (),
            event_type="CHECKPOINT",
            actor_role=Role.HOLDOUT_CUSTODIAN,
            metadata={
                "fresh_custody": {
                    "artifact_sha256": receipt["sha256"],
                    "artifact_record_hash": receipt["registry_record_hash"],
                    "journal_head_hash": sealed_journal_head,
                    "journal_identity_sha256": sealed_journal_identity,
                    "protocol_hash": frozen_study.protocol_hash,
                    "seal_hash": seal.seal_hash,
                    "study_version": frozen_study.version,
                }
            },
        )
        self._save_manifest(manifest)

        started_event_id: str | None = None

        def selector(name: str) -> RegisteredArtifactSelector:
            record = manifest["artifacts"][name]
            return RegisteredArtifactSelector(
                record["sha256"], record["registry_record_hash"]
            )

        def confirmatory(
            charged: _ChargedResourceAuthority,
        ) -> tuple[Any, dict[str, Any], _ChargedResourceAuthority]:
            nonlocal started_event_id
            reveal_authority = ConfirmatoryRevealAuthority(
                protocol=selector("frozen_protocol"),
                source_inventory=selector("frozen_source_inventory"),
                configuration_inventory=selector(
                    "frozen_configuration_inventory"
                ),
                split_manifest=selector("frozen_confirmatory_split"),
                blind_interpretation=selector("blind_interpretation"),
                midrun_review=selector("midrun_review"),
                resource_charge=charged.selector,
                resource_charge_ledger_event_id=charged.ledger_event_id,
                confirmatory_validity_units=charged.validity_units,
            )
            started_artifact_names = (
                "frozen_protocol",
                "frozen_source_inventory",
                "frozen_configuration_inventory",
                "frozen_confirmatory_split",
                "blind_interpretation",
                "midrun_review",
                "resource_runtime_confirmatory_charge",
                "fresh_custody_receipt",
            )
            started_records = tuple(
                manifest["artifacts"][name]
                for name in started_artifact_names
            )
            resource_descriptors = self._resource_authority_descriptors(
                self._resource_authority_records(str(manifest["run_id"]))
            )
            if (
                not resource_descriptors
                or resource_descriptors[-1]["logical_type"]
                != "resource_runtime_confirmatory_charge"
                or resource_descriptors[-1]["state_sha256"]
                != charged.selector.artifact_sha256
            ):
                raise OrchestrationError(
                    "confirmatory STARTED lacks the live resource authority"
                )
            started_metadata = {
                "schema_version": SCHEMA_VERSION,
                "evidence_class": "ARCHITECTURE_CONTROL",
                "execution_kind": (
                    "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
                ),
                "initialization": False,
                "evaluator_keys": [],
                "artifact_types": list(started_artifact_names),
                "artifact_record_hashes": [
                    record["registry_record_hash"]
                    for record in started_records
                ],
                "artifact_descriptors": [
                    {
                        "logical_type": record["logical_type"],
                        "sha256": record["sha256"],
                        "registry_record_hash": record[
                            "registry_record_hash"
                        ],
                        "parent_artifacts": list(
                            record.get("parent_artifacts", ())
                        ),
                        "parent_record_hashes": [
                            self._registry(str(manifest["run_id"]))
                            .get_metadata(parent)
                            .record_hash
                            for parent in record.get(
                                "parent_artifacts", ()
                            )
                        ],
                    }
                    for record in started_records
                ],
                "resource_authority_checkpoint": dict(
                    resource_descriptors[-1]
                ),
                "fresh_custody": {
                    "artifact_sha256": receipt["sha256"],
                    "artifact_record_hash": receipt[
                        "registry_record_hash"
                    ],
                    "journal_head_hash": sealed_journal_head,
                    "journal_identity_sha256": sealed_journal_identity,
                    "protocol_hash": frozen_study.protocol_hash,
                    "seal_hash": seal.seal_hash,
                    "study_version": frozen_study.version,
                },
            }
            start_event = LedgerEvent.create(
                run_id=str(manifest["run_id"]),
                event_id=f"event-{int(manifest['event_count']) + 1:04d}",
                timestamp=_utc_now(),
                actor_role=Role.ORCHESTRATOR,
                state_before=MacroState.CONFIRM,
                requested_state_after=MacroState.CONFIRM,
                artifact_hashes=tuple(
                    record["sha256"] for record in started_records
                ),
                code_version=str(manifest["code_fingerprint"]),
                configuration_hash=str(manifest["configuration_sha256"]),
                dataset_identifiers=tuple(manifest["fixture_identifiers"]),
                random_seeds=tuple(manifest["random_seeds"]),
                evaluator_outputs=(),
                reason=(
                    "non-evidentiary simulated architecture-control execution "
                    "started before fixture reveal"
                ),
                prior_event_hash=str(manifest["ledger_head_hash"]),
                event_type="CHECKPOINT",
                metadata=started_metadata,
            )

            released = RecoveryManager(
                self.root,
                ledger_validator=lambda path: (
                    self._foundation_ledger_validation(path)
                ),
            ).run_non_evidentiary_simulated_fixture(
                ledger_path=(
                    Path("runs") / str(manifest["run_id"]) / "events.jsonl"
                ),
                study_version=frozen_study,
                fresh_custody_evidence=FreshCustodyEvidence(
                    receipt["sha256"],
                    receipt["registry_record_hash"],
                    receipt_event_id,
                ),
                reveal_authority=reveal_authority,
                artifact_registry=self._registry(str(manifest["run_id"])),
                custody_provider=custody_adapter,
                validity_snapshot=charged.validity_snapshot,
                start_event=start_event,
                evaluator_spec=ConfirmatoryEvaluatorSpec(),
                requester=Role.EXPERIMENT_RUNNER.value,
                reason=(
                    "single frozen non-evidentiary simulated architecture-control run"
                ),
                requested_at=manifest["created_at"],
            )
            admitted = EventLedger(
                self.root,
                Path("runs")
                / str(manifest["run_id"])
                / "events.jsonl",
            ).validate(raise_on_error=True)
            if (
                admitted.event_count != int(manifest["event_count"]) + 1
                or not admitted.events
                or admitted.events[-1] != start_event
                or admitted.head_hash != start_event.event_hash
            ):
                raise OrchestrationError(
                    "confirmatory STARTED ledger synchronization failed"
                )
            manifest["event_count"] = admitted.event_count
            manifest["ledger_head_hash"] = admitted.head_hash
            started_event_id = start_event.event_id
            self._save_manifest(manifest)
            return released[0], released[1], charged

        release, confirmatory_output, confirmatory_charge = self._run_with_resources(
            manifest,
            experiment_id=f"{manifest['run_id']}:confirmatory",
            validity_stage="CONFIRMATORY",
            validity_units=4,
            charged_operation=confirmatory,
        )
        if started_event_id is None:
            raise OrchestrationError(
                "confirmatory reveal did not publish its STARTED authority"
            )
        if (
            not custody_adapter.status.invalidated
            or custody_adapter.status.confirmatory_claims_valid
        ):
            raise OrchestrationError(
                "simulated custody did not remain non-evidentiary"
            )
        expected_confirmatory_output_fields = {
            "schema_version",
            "kind",
            "control_mean",
            "treatment_mean",
            "primary_estimate",
            "n_control",
            "n_treatment",
        }
        if set(confirmatory_output) != expected_confirmatory_output_fields:
            raise OrchestrationError(
                "closed confirmatory evaluator returned an invalid schema"
            )
        estimate = confirmatory_output["primary_estimate"]
        with custody_adapter.admission_guard() as live_custody:
            custody_status = live_custody.status
            journal_head = live_custody.journal_head_hash
            journal_sha256 = live_custody.journal_sha256
            journal_size = live_custody.journal_size
            journal_identity = live_custody.journal_identity_sha256
        custody = {
            "kind": "SIMULATED_HOLDOUT_CUSTODY",
            "study_id": frozen_study.study_id,
            "study_version": frozen_study.version,
            "custody_independence": custody_adapter.custody_label,
            "holdout_identity_hash": seal.holdout_identity_hash,
            "split_manifest_hash": seal.split_manifest_hash,
            "sealing_time": seal.sealed_at,
            "authorized_access_count": custody_status.authorized_access_count,
            "access_requester": release.requester,
            "access_reason": release.reason,
            "protocol_hash": seal.protocol_hash,
            "code_hash": seal.code_hash,
            "configuration_hash": seal.configuration_hash,
            "source_inventory_sha256": source_inventory_hash,
            "configuration_inventory_sha256": configuration_inventory_hash,
            "split_manifest_artifact_sha256": split_record["sha256"],
            "midrun_review_sha256": manifest["artifacts"]["midrun_review"][
                "sha256"
            ],
            "resource_charge_artifact_sha256": (
                confirmatory_charge.selector.artifact_sha256
            ),
            "resource_charge_ledger_event_id": (
                confirmatory_charge.ledger_event_id
            ),
            "fresh_custody_receipt_sha256": receipt["sha256"],
            "fresh_custody_receipt_event_id": receipt_event_id,
            "confirmatory_started_event_id": started_event_id,
            "confirmatory_validity_units": confirmatory_charge.validity_units,
            "pre_unblinding_interpretation_hash": seal.pre_unblinding_interpretation_hash,
            "seal_hash": seal.seal_hash,
            "release_event": asdict(release),
            "access_records": [asdict(record) for record in custody_adapter.access_records],
            "confirmatory_claims_valid": custody_status.confirmatory_claims_valid,
            "evidence_class": "ARCHITECTURE_CONTROL",
            "execution_kind": "SIMULATED_ARCHITECTURE_CONTROL_STARTED",
            "scientific_evidence": False,
            "durable_journal": custody_status.durable_journal,
            "journal_path": custody_journal.as_posix(),
            "journal_head_hash": journal_head,
            "journal_sha256": journal_sha256,
            "journal_size": journal_size,
            "journal_identity_sha256": journal_identity,
            "genuine_independence_claimed": False,
        }
        custody_record = self._artifact(
            manifest,
            "custody_record",
            custody,
            creator=Role.HOLDOUT_CUSTODIAN.value,
            parents=(
                protocol_artifact_hash,
                source_inventory_hash,
                configuration_inventory_hash,
                split_record["sha256"],
                blind_hash,
                manifest["artifacts"]["midrun_review"]["sha256"],
                confirmatory_charge.selector.artifact_sha256,
                receipt["sha256"],
            ),
        )
        control_mean = confirmatory_output["control_mean"]
        treatment_mean = confirmatory_output["treatment_mean"]
        result_core = {
            "primary_estimate": estimate,
            "control_mean": control_mean,
            "treatment_mean": treatment_mean,
            "n_control": confirmatory_output["n_control"],
            "n_treatment": confirmatory_output["n_treatment"],
        }
        results = {"kind": "MACHINE_READABLE_RESULTS", "evidence_class": "ARCHITECTURE_CONTROL", "outcome_pattern": scenario, "dataset_fixture_ids": ["synthetic-confirmatory-v1"], "random_seeds": [20260812], "code_fingerprint": manifest["code_fingerprint"], "configuration_sha256": manifest["configuration_sha256"], "input_hashes": {"frozen_protocol": protocol_artifact_hash, "blind_interpretation": blind_hash, "custody_record": custody_record["sha256"], "frozen_source_inventory": source_inventory_hash, "frozen_configuration_inventory": configuration_inventory_hash}, "scientific_protocol_sha256": protocol_hash, "frozen_fixture": fixture, **result_core, "output_hashes": {"result_core": _sha256(_canonical_bytes(result_core))}, "confirmatory_access_count": 1, "tuned_after_reveal": False, "scientific_evidence": False}
        self._artifact(manifest, "machine_results", results, creator=Role.EXPERIMENT_RUNNER.value, parents=(protocol_artifact_hash, blind_hash, custody_record["sha256"], source_inventory_hash, configuration_inventory_hash))
        names = ("custody_record", "machine_results")
        self._evaluate(manifest, "E0:CONFIRM", EvaluatorClass.E0, Role.ORCHESTRATOR, names, (RCheck.R0, RCheck.R2, RCheck.R3, RCheck.R4), producer=Role.EXPERIMENT_RUNNER)
        self._evaluate(manifest, "E2:CONFIRM", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, names, (RCheck.R2, RCheck.R3, RCheck.R4), producer=Role.EXPERIMENT_RUNNER)
        self._evaluate(manifest, "E3:CONFIRM", EvaluatorClass.E3, Role.ADVERSARIAL_REVIEWER, names, (RCheck.R3, RCheck.R4, RCheck.R5), producer=Role.EXPERIMENT_RUNNER)
        self._append_event(
            manifest,
            "CONFIRM",
            "CONFIRM",
            "non-evidentiary simulated architecture-control result completed and frozen",
            names,
            (
                ("E0:CONFIRM", "E2:CONFIRM", "E3:CONFIRM")
                if scenario in {"null", "reversal", "unstable"}
                else ()
            ),
            event_type="CHECKPOINT",
            metadata={
                "evidence_class": "ARCHITECTURE_CONTROL",
                "execution_kind": (
                    "SIMULATED_ARCHITECTURE_CONTROL_COMPLETED"
                ),
                "scientific_evidence": False,
            },
        )
        self._save_manifest(manifest)
        terminal_by_scenario = {
            "null": ("NEGATIVE_RESULT", "confirmatory estimate is the preregistered null outcome"),
            "reversal": ("INCONCLUSIVE", "confirmatory direction contradicts the development signal"),
            "unstable": ("INCONCLUSIVE", "confirmatory observations are deliberately unstable and high variance"),
        }
        if scenario in terminal_by_scenario:
            destination, terminal_reason = terminal_by_scenario[scenario]
            self._queue_terminal(
                manifest,
                destination,
                terminal_reason,
                evidence={
                    "outcome_pattern": scenario,
                    "primary_estimate": estimate,
                    "machine_results_sha256": manifest["artifacts"]["machine_results"]["sha256"],
                },
            )

    def _writing_rows(self, manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Derive every published number from frozen machine artifacts."""

        machine_results = self._json_artifact_payload(manifest, "machine_results")
        benchmark = self._json_artifact_payload(manifest, "workflow_benchmark")
        benchmark_results = benchmark.get("results")
        if not isinstance(benchmark_results, list):
            raise OrchestrationError("workflow benchmark has no machine-readable results")
        scenario_rows = {
            item.get("scenario"): item
            for item in benchmark_results
            if isinstance(item, dict)
        }
        required = ("signal", "null", "reversal")
        if any(name not in scenario_rows for name in required):
            raise OrchestrationError("workflow benchmark omits a required writing scenario")
        signal_estimate = machine_results.get("primary_estimate")
        null_effect = scenario_rows["null"].get("statistics", {}).get("observed_difference")
        reversal_effect = (
            scenario_rows["reversal"]
            .get("statistics", {})
            .get("regime_effects", {})
            .get("confirmatory")
        )
        if any(
            isinstance(value, bool) or not isinstance(value, (int, float))
            for value in (signal_estimate, null_effect, reversal_effect)
        ):
            raise OrchestrationError("machine-readable writing effects are invalid")
        return [
            {
                "task": "signal",
                "decision": scenario_rows["signal"]["decision"],
                "effect_size": signal_estimate,
            },
            {
                "task": "true-null",
                "decision": scenario_rows["null"]["decision"],
                "effect_size": null_effect,
            },
            {
                "task": "reversal",
                "decision": scenario_rows["reversal"]["decision"],
                "effect_size": reversal_effect,
            },
        ]

    def _handler_claims(self, manifest: dict[str, Any]) -> None:
        if not self._validate_live_inventories(manifest):
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "live code or configuration drifted after confirmatory execution",
                evidence={"stage": "CLAIMS"},
            )
            return
        result_hash = manifest["artifacts"]["machine_results"]["sha256"]
        protocol_hash = manifest["protocol_hash"]
        benchmark_hash = manifest["artifacts"]["workflow_benchmark"]["sha256"]
        rows = self._writing_rows(manifest)
        work = _secure_directory(
            self.root,
            Path(".scientist-one-build/tmp") / str(manifest["run_id"]) / "write",
            create=True,
        )
        expected_table_bytes = render_results_table_bytes(rows)
        expected_figure_bytes = render_svg_effect_figure_bytes(rows)
        table_path = write_results_table(rows, work / "results.csv", root=self.root)
        figure_path = write_svg_effect_figure(rows, work / "effects.svg", root=self.root)
        output_parents = (result_hash, benchmark_hash)
        table_record = self._artifact_from_file(
            manifest,
            "results_table",
            table_path,
            creator=Role.PAPER_WRITER.value,
            mime_type="text/csv",
            parents=output_parents,
            expected_bytes=expected_table_bytes,
        )
        figure_record = self._artifact_from_file(
            manifest,
            "results_figure",
            figure_path,
            creator=Role.PAPER_WRITER.value,
            mime_type="image/svg+xml",
            parents=output_parents,
            expected_bytes=expected_figure_bytes,
        )

        source_inventory = self._json_artifact_payload(
            manifest, "frozen_source_inventory"
        )
        configuration_inventory = self._json_artifact_payload(
            manifest, "frozen_configuration_inventory"
        )
        if not self._validate_live_inventories(manifest):
            raise OrchestrationError("live inventory changed during claim materialization")
        source_inventory_hash = manifest["artifacts"]["frozen_source_inventory"]["sha256"]
        configuration_inventory_hash = manifest["artifacts"]["frozen_configuration_inventory"]["sha256"]

        machine_results = self._json_artifact_payload(manifest, "machine_results")
        evidence_payloads: tuple[tuple[str, EvidenceKind, dict[str, Any], str, tuple[str, ...]], ...] = (
            ("ev-hypothesis", EvidenceKind.HYPOTHESIS, {"hypothesis_id": "hypothesis-synthetic-primary-v1", "artifact_sha256": manifest["artifacts"]["hypothesis_set"]["sha256"]}, "hypothesis-synthetic-primary-v1", (manifest["artifacts"]["hypothesis_set"]["sha256"],)),
            ("ev-estimand", EvidenceKind.ESTIMAND, {"estimand_id": "treatment_mean_minus_control_mean", "protocol_sha256": protocol_hash}, "treatment_mean_minus_control_mean", (manifest["artifacts"]["frozen_protocol"]["sha256"],)),
            ("ev-fixture", EvidenceKind.DATASET_OR_FIXTURE, {"fixture_ids": machine_results["dataset_fixture_ids"], "custody_sha256": manifest["artifacts"]["custody_record"]["sha256"]}, "synthetic-confirmatory-v1", (manifest["artifacts"]["custody_record"]["sha256"],)),
            ("ev-protocol", EvidenceKind.PROTOCOL_VERSION, {"scientific_protocol_sha256": protocol_hash, "artifact_sha256": manifest["artifacts"]["frozen_protocol"]["sha256"]}, "frozen protocol version one", (manifest["artifacts"]["frozen_protocol"]["sha256"],)),
            ("ev-code", EvidenceKind.CODE, {"code_fingerprint": manifest["code_fingerprint"], "configuration_sha256": manifest["configuration_sha256"], "source_inventory_sha256": source_inventory_hash, "configuration_inventory_sha256": configuration_inventory_hash, "source_inventory_aggregate": source_inventory["aggregate_sha256"], "configuration_inventory_aggregate": configuration_inventory["aggregate_sha256"]}, "frozen pre-confirm source and configuration inventories", (source_inventory_hash, configuration_inventory_hash)),
            ("ev-result", EvidenceKind.RESULT, {"artifact_sha256": result_hash, "primary_estimate": machine_results["primary_estimate"]}, "machine-readable primary result", (result_hash,)),
            ("ev-statistics", EvidenceKind.STATISTICAL_ANALYSIS, {"method": "difference_of_arithmetic_means_v1", "recomputed_estimate": rows[0]["effect_size"], "result_core_sha256": machine_results["output_hashes"]["result_core"]}, "difference of arithmetic means", (result_hash,)),
            ("ev-robustness", EvidenceKind.ROBUSTNESS, {"benchmark_sha256": benchmark_hash, "required_scenarios": ["signal", "null", "reversal"]}, "six-scenario known-answer benchmark", (benchmark_hash,)),
            ("ev-figure-table", EvidenceKind.FIGURE_OR_TABLE, {"results_table_sha256": table_record["sha256"], "results_figure_sha256": figure_record["sha256"]}, "results_table results_figure", (table_record["sha256"], figure_record["sha256"])),
            ("ev-source", EvidenceKind.SOURCE_CITATION, {"fixture_id": "synthetic-confirmatory-v1", "external_source": False, "locally_verified_by": "custody_and_machine_results"}, "local synthetic fixture; no external citation", (result_hash, manifest["artifacts"]["custody_record"]["sha256"])),
            ("ev-scope", EvidenceKind.SCOPE_QUALIFIER, {"scope": "synthetic fixture only", "external_generalization": False}, "synthetic fixture only", (manifest["artifacts"]["research_charter"]["sha256"],)),
            ("ev-limitations", EvidenceKind.LIMITATION, {"limitations": ["does not establish external novelty", "does not establish real-world validity", "simulated custody is non-independent"]}, "does not establish external novelty; does not establish real-world validity; simulated custody is non-independent", (manifest["artifacts"]["custody_record"]["sha256"],)),
        )
        node_specs: list[tuple[str, EvidenceKind, str, str]] = []
        for evidence_id, kind, payload, description, parents in evidence_payloads:
            logical_type = f"claim_evidence.{kind.value}"
            record = self._artifact(
                manifest,
                logical_type,
                {"kind": logical_type, "evidence_id": evidence_id, **payload},
                creator=Role.CLAIM_VERIFIER.value,
                parents=parents,
            )
            node_specs.append((evidence_id, kind, record["sha256"], description))

        material_claim = MaterialClaim(
            "claim-synthetic-primary-v1",
            "In the frozen non-evidentiary architecture-control fixture, the treatment mean exceeds control by exactly 1.0.",
            tuple(EvidenceLink(evidence_id, kind) for evidence_id, kind, _, _ in node_specs),
            Role.STATISTICIAN,
            confirmatory=False,
            evidence_use=ClaimEvidenceUse.SYSTEM_FIXTURE,
        )
        registry = self._registry(str(manifest["run_id"]))
        graph_model = ClaimEvidenceGraph(
            evidence_resolver=artifact_registry_resolver(
                registry, resolver_id="run-artifact-registry"
            )
        )
        for evidence_id, kind, digest, description in node_specs:
            unbound_node = EvidenceNode(
                evidence_id,
                kind,
                digest,
                description,
                verified=True,
                frozen=True,
                supports_claim=True,
                contradicts_claim=False,
                locally_verifiable=True,
            )
            support_receipt = EvidenceSupportReceipt.for_claim(
                material_claim,
                unbound_node,
                verifier_id="claim-verifier-context-v1",
                verification_result="PASS",
                supports_claim=True,
                contradicts_claim=False,
                locally_verifiable=True,
                rationale=(
                    f"The frozen {kind.value} artifact was locally resolved, "
                    "content-hash verified, and found to support only the bounded "
                    "synthetic claim without contradiction."
                ),
            )
            support_record = self._artifact(
                manifest,
                f"claim_support_receipt.{kind.value}",
                support_receipt.to_dict(),
                creator=Role.CLAIM_VERIFIER.value,
                parents=(digest,),
            )
            if support_record["sha256"] != support_receipt.sha256:
                raise OrchestrationError("claim support receipt canonical hash mismatch")
            graph_model.add_evidence(
                EvidenceNode(
                    evidence_id,
                    kind,
                    digest,
                    description,
                    verified=True,
                    frozen=True,
                    supports_claim=True,
                    contradicts_claim=False,
                    locally_verifiable=True,
                    verification_receipt_hash=support_record["sha256"],
                )
            )
        graph_model.add_claim(material_claim)
        custody_valid = self._validate_live_custody(manifest)
        decision = graph_model.verify_claim(
            material_claim.claim_id,
            verifier_id="claim-verifier-context-v1",
            verifier_role=Role.CLAIM_VERIFIER,
            confirmatory_evidence_valid=custody_valid,
            raise_on_rejection=True,
        )
        if decision.decision is not ClaimDecision.ELIGIBLE:
            raise OrchestrationError("typed claim graph rejected the primary claim")
        authoritative_view = list(
            graph_model.writer_view(
                include_nonscientific=True,
                confirmatory_evidence_valid=custody_valid,
            )
        )
        if len(authoritative_view) != 1:
            raise OrchestrationError("typed claim graph produced an invalid writer view")
        writer_claim = dict(authoritative_view[0])
        writer_claim.update(
            {
                "hypothesis_id": "hypothesis-synthetic-primary-v1",
                "estimand_id": "treatment_mean_minus_control_mean",
                "dataset_or_fixture_id": "synthetic-confirmatory-v1",
                "protocol_hash": protocol_hash,
                "code_hash": manifest["code_fingerprint"],
                "result_artifact_hash": result_hash,
                "statistical_analysis_hash": manifest["artifacts"]["claim_evidence.statistical_analysis"]["sha256"],
                "robustness_evidence_hashes": [manifest["artifacts"]["claim_evidence.robustness_evidence"]["sha256"]],
                "figure_or_table_ids": ["results_table", "results_figure"],
                "source_citation_ids": ["local-synthetic-fixture-v1"],
                "verifier_artifact_hash": decision.sha256,
            }
        )
        graph = {
            "kind": "CLAIM_EVIDENCE_GRAPH",
            "graph": graph_model.to_dict(),
            "graph_sha256": graph_model.sha256,
            "writer_view": [writer_claim],
            "writer_contract": "derived_only_from_typed_ELIGIBLE_decisions",
        }
        self._artifact(
            manifest,
            "claim_graph",
            graph,
            creator=Role.CLAIM_VERIFIER.value,
            parents=tuple(
                manifest["artifacts"][f"claim_evidence.{kind.value}"]["sha256"]
                for kind in EvidenceKind
            )
            + tuple(
                manifest["artifacts"][f"claim_support_receipt.{kind.value}"]["sha256"]
                for kind in EvidenceKind
            ),
        )
        self._evaluate(manifest, "E0:CLAIMS", EvaluatorClass.E0, Role.ORCHESTRATOR, ("claim_graph",), (RCheck.R6,), producer=Role.CLAIM_VERIFIER)
        self._evaluate(manifest, "E2:CLAIMS", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, ("claim_graph",), (RCheck.R6,), producer=Role.CLAIM_VERIFIER)

    def _handler_write(self, manifest: dict[str, Any]) -> None:
        if not self._validate_live_inventories(manifest):
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "live code or configuration drifted before writing",
                evidence={"stage": "WRITE"},
            )
            return
        graph = self._json_artifact_payload(manifest, "claim_graph")
        stored_view = graph.get("writer_view")
        graph_payload = graph.get("graph")
        if not isinstance(stored_view, list) or not isinstance(graph_payload, dict):
            raise OrchestrationError("serialized claim graph is incomplete")
        try:
            custody_valid = self._validate_live_custody(manifest)
            live_graph = ClaimEvidenceGraph.from_dict(
                graph_payload,
                evidence_resolver=artifact_registry_resolver(
                    self._registry(str(manifest["run_id"])),
                    resolver_id="run-artifact-registry",
                ),
            )
            for claim in live_graph.claims:
                live_graph.verify_claim(
                    claim.claim_id,
                    verifier_id="claim-verifier-context-v1",
                    verifier_role=Role.CLAIM_VERIFIER,
                    confirmatory_evidence_valid=custody_valid,
                    raise_on_rejection=True,
                )
            fresh_view = list(
                live_graph.writer_view(
                    include_nonscientific=True,
                    confirmatory_evidence_valid=custody_valid,
                )
            )
            fresh_graph_payload = live_graph.to_dict()
        except Exception as exc:
            raise OrchestrationError("claim eligibility could not be freshly reverified") from exc
        if (
            fresh_graph_payload != graph_payload
            or live_graph.sha256 != graph.get("graph_sha256")
        ):
            raise OrchestrationError("serialized claim graph or digest is stale")
        if len(fresh_view) != len(stored_view) or not fresh_view:
            raise OrchestrationError("serialized writer view is stale")
        eligible: list[dict[str, Any]] = []
        for fresh, stored in zip(fresh_view, stored_view, strict=True):
            if not isinstance(stored, dict):
                raise OrchestrationError("serialized writer claim is malformed")
            decision = live_graph.require_eligible(
                str(fresh["claim_id"]),
                confirmatory_evidence_valid=custody_valid,
            )
            expected = dict(fresh)
            expected.update(
                {
                    "hypothesis_id": "hypothesis-synthetic-primary-v1",
                    "estimand_id": "treatment_mean_minus_control_mean",
                    "dataset_or_fixture_id": "synthetic-confirmatory-v1",
                    "protocol_hash": manifest["protocol_hash"],
                    "code_hash": manifest["code_fingerprint"],
                    "result_artifact_hash": manifest["artifacts"]["machine_results"]["sha256"],
                    "statistical_analysis_hash": manifest["artifacts"]["claim_evidence.statistical_analysis"]["sha256"],
                    "robustness_evidence_hashes": [manifest["artifacts"]["claim_evidence.robustness_evidence"]["sha256"]],
                    "figure_or_table_ids": ["results_table", "results_figure"],
                    "source_citation_ids": ["local-synthetic-fixture-v1"],
                    "verifier_artifact_hash": decision.sha256,
                }
            )
            if stored != expected:
                raise OrchestrationError("serialized writer view differs from fresh eligibility")
            eligible.append(expected)
        if any(claim.get("verifier_decision") != "ELIGIBLE" for claim in eligible):
            raise OrchestrationError("WRITE may consume only a non-empty eligible writer view")
        work = _secure_directory(self.root, Path(".scientist-one-build/tmp") / str(manifest["run_id"]) / "write", create=True)
        rows = self._writing_rows(manifest)
        expected_table_bytes = render_results_table_bytes(rows)
        expected_figure_bytes = render_svg_effect_figure_bytes(rows)
        table = write_results_table(rows, work / "results.csv", root=self.root)
        figure = write_svg_effect_figure(rows, work / "effects.svg", root=self.root)
        for logical_type, generated, expected_bytes in (
            ("results_table", table, expected_table_bytes),
            ("results_figure", figure, expected_figure_bytes),
        ):
            record = manifest["artifacts"].get(logical_type)
            if not isinstance(record, dict):
                raise OrchestrationError(f"claim verification did not freeze {logical_type}")
            generated_bytes = read_confined_bytes(
                self.root,
                generated.relative_to(self.root),
                reject_hardlinks=True,
                max_bytes=8 * 1024 * 1024,
            )
            if (
                generated_bytes is None
                or generated_bytes != expected_bytes
                or _sha256(generated_bytes) != record.get("sha256")
            ):
                raise OrchestrationError(f"{logical_type} differs from its claim evidence binding")
        paper_manifest = {"package_kind": "DEMO_RESEARCH_PACKAGE", "protocol_hash": manifest["protocol_hash"]}
        table_reference = table.relative_to(self.root)
        figure_reference = figure.relative_to(self.root)
        expected_paper_bytes = render_demo_paper_bytes(
            paper_manifest,
            eligible,
            table_reference,
            figure_reference,
        )
        paper = write_demo_paper(
            paper_manifest,
            eligible,
            table_reference,
            figure_reference,
            work / "paper.md",
            root=self.root,
        )
        parent = (manifest["artifacts"]["machine_results"]["sha256"], manifest["artifacts"]["claim_graph"]["sha256"])
        self._artifact_from_file(
            manifest,
            "demo_paper",
            paper,
            creator=Role.PAPER_WRITER.value,
            mime_type="text/markdown",
            parents=parent,
            expected_bytes=expected_paper_bytes,
        )
        names = ("results_table", "results_figure", "demo_paper")
        self._evaluate(manifest, "E0:WRITE", EvaluatorClass.E0, Role.ORCHESTRATOR, names, (RCheck.R6,), producer=Role.PAPER_WRITER)
        self._evaluate(manifest, "E2:WRITE", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, names, (RCheck.R6,), producer=Role.PAPER_WRITER)

    @_project_command
    def verify(self, run_id: str) -> dict[str, Any]:
        operation = self._fixture_operation_receipt(run_id)
        if operation is not None:
            if self._manifest_name_present(run_id):
                raise OrchestrationError(
                    "run contains ambiguous legacy and vNext authorities"
                )
            return self._verify_vnext_fixture(run_id, operation)
        manifest = self.load_manifest(run_id)
        external_checkpoint_valid = True
        try:
            self._assert_no_newer_external_checkpoint(manifest)
        except OrchestrationError:
            external_checkpoint_valid = False
        manager = RecoveryManager(
            self.root,
            ledger_validator=lambda path: self._foundation_ledger_validation(path),
        )
        ledger = manager.validate_ledger(
            (self._run_dir(run_id) / "events.jsonl").relative_to(self.root)
        )
        resource_authority_history_valid = True
        try:
            self._validate_resource_authority_ledger(
                self._resource_authority_records(run_id), ledger.events
            )
        except OrchestrationError:
            resource_authority_history_valid = False
        artifacts = manager.validate_artifacts(list(manifest["artifacts"].values()))
        registry = self._registry(run_id).verify_all()
        recovery = self._recovery_report(manifest)
        contract_ok = manifest["current_state"] in MACRO_STATES or manifest["current_state"] in TERMINAL_STATES
        state_matches_ledger = recovery.derived_state == manifest.get("current_state")
        derived_terminal = (
            recovery.derived_state
            if recovery.derived_state in TERMINAL_STATES
            else None
        )
        expected_outcome = (
            "COMPLETE_DEMO_ONLY"
            if derived_terminal == "READY_FOR_HUMAN_REVIEW"
            else derived_terminal or "IN_PROGRESS"
        )
        terminal_projection_valid = (
            manifest.get("terminal_state") == derived_terminal
            and manifest.get("outcome") == expected_outcome
        )
        manifest_matches_ledger = (
            manifest.get("ledger_head_hash") == ledger.head_hash
            and manifest.get("event_count") == ledger.event_count
        )
        recovery_safe = recovery.action.value not in {
            "STOP_SECURITY",
            "STOP_SCIENTIFIC_INVALIDITY",
            "NEW_STUDY_REQUIRED",
        }
        if derived_terminal in {"STOP_SECURITY", "STOP_SCIENTIFIC_INVALIDITY"}:
            # A fully verified persisted stop is a correct integrity outcome,
            # not permission to resume. Additional or stale recovery failures
            # still fail verification; every independent check below remains.
            recovery_safe = (
                recovery.action.value == derived_terminal
                and recovery.reasons
                == (f"PERSISTED_TERMINAL_STATE:{derived_terminal}",)
                and recovery.ledger_valid is True
                and recovery.artifacts_valid is True
                and not recovery.artifact_issues
                and recovery.ledger_event_count == ledger.event_count
                and recovery.ledger_head_hash == ledger.head_hash
            )
        registry_records = {record.sha256: record for record in registry.records}
        registry_matches_manifest = registry.valid and len(registry_records) == len(manifest["artifacts"])
        if registry_matches_manifest:
            for record in manifest["artifacts"].values():
                stored = registry_records.get(record["sha256"])
                if stored is None or (
                    stored.logical_type != record["logical_type"]
                    or stored.record_hash != record.get("registry_record_hash")
                    or stored.path != record.get("registry_path")
                    or stored.metadata_path != record.get("registry_metadata_path")
                    or stored.parent_artifacts != tuple(record.get("parent_artifacts", ()))
                ):
                    registry_matches_manifest = False
                    break
        registry_closure_valid = registry_matches_manifest
        if registry_closure_valid:
            roots = {
                digest
                for event in ledger.events
                for digest in event.get("artifact_hashes", ())
                if isinstance(digest, str)
            }
            closure: set[str] = set()
            pending = list(roots)
            while pending:
                digest = pending.pop()
                if digest in closure:
                    continue
                stored = registry_records.get(digest)
                if stored is None:
                    registry_closure_valid = False
                    break
                closure.add(digest)
                pending.extend(stored.parent_artifacts)
            if closure != set(registry_records):
                registry_closure_valid = False
        ledger_artifact_projection: dict[str, str] = {}
        ledger_record_projection: dict[str, str] = {}
        ledger_projection_valid = True
        for event in ledger.events:
            artifact_types = event.get("metadata", {}).get("artifact_types", [])
            artifact_record_hashes = event.get("metadata", {}).get(
                "artifact_record_hashes", []
            )
            artifact_descriptors = event.get("metadata", {}).get(
                "artifact_descriptors", []
            )
            artifact_hashes = event.get("artifact_hashes", [])
            if (
                not isinstance(artifact_types, list)
                or not isinstance(artifact_record_hashes, list)
                or not isinstance(artifact_descriptors, list)
                or not isinstance(artifact_hashes, list)
                or len(artifact_types) != len(artifact_hashes)
                or len(artifact_record_hashes) != len(artifact_hashes)
                or len(artifact_descriptors) != len(artifact_hashes)
            ):
                if artifact_hashes:
                    ledger_projection_valid = False
                    break
                continue
            for logical_type, digest, record_hash, descriptor in zip(
                artifact_types,
                artifact_hashes,
                artifact_record_hashes,
                artifact_descriptors,
                strict=True,
            ):
                if (
                    not isinstance(logical_type, str)
                    or not isinstance(digest, str)
                    or not isinstance(record_hash, str)
                    or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                    or re.fullmatch(r"[0-9a-f]{64}", record_hash) is None
                ):
                    ledger_projection_valid = False
                    break
                manifest_record = manifest.get("artifacts", {}).get(logical_type)
                stored_record = registry_records.get(digest)
                expected_descriptor = {
                    "logical_type": logical_type,
                    "sha256": digest,
                    "registry_record_hash": record_hash,
                    "parent_artifacts": (
                        list(stored_record.parent_artifacts)
                        if stored_record is not None
                        else []
                    ),
                    "parent_record_hashes": (
                        [
                            registry_records[parent].record_hash
                            for parent in stored_record.parent_artifacts
                            if parent in registry_records
                        ]
                        if stored_record is not None
                        else []
                    ),
                }
                if (
                    not isinstance(manifest_record, Mapping)
                    or stored_record is None
                    or len(expected_descriptor["parent_record_hashes"])
                    != len(stored_record.parent_artifacts)
                    or descriptor != expected_descriptor
                ):
                    ledger_projection_valid = False
                    break
                prior = ledger_artifact_projection.get(logical_type)
                prior_record = ledger_record_projection.get(logical_type)
                if (
                    (prior is not None and prior != digest)
                    or (prior_record is not None and prior_record != record_hash)
                ):
                    ledger_projection_valid = False
                    break
                ledger_artifact_projection[logical_type] = digest
                ledger_record_projection[logical_type] = record_hash
            if not ledger_projection_valid:
                break
        for logical_type, digest in ledger_artifact_projection.items():
            record = manifest["artifacts"].get(logical_type)
            stored = registry_records.get(digest)
            if (
                not isinstance(record, dict)
                or record.get("sha256") != digest
                or stored is None
                or stored.logical_type != logical_type
                or stored.record_hash != record.get("registry_record_hash")
                or stored.record_hash != ledger_record_projection.get(logical_type)
            ):
                ledger_projection_valid = False
                break
        transition_edges = [
            f"{event['state_before']}->{event['requested_state_after']}"
            for event in ledger.events
            if event.get("event_type") in {"TRANSITION", "SECURITY_STOP"}
        ]
        ledger_sequence_valid = transition_edges == manifest.get("completed_transitions", [])
        provenance_valid = all(
            event.get("run_id") == run_id
            and event.get("code_version") == manifest.get("code_fingerprint")
            and event.get("configuration_hash") == manifest.get("configuration_sha256")
            and event.get("dataset_identifiers") == manifest.get("fixture_identifiers")
            and event.get("random_seeds") == manifest.get("random_seeds")
            for event in ledger.events
        )
        receipts = manifest.get("typed_transition_receipts", [])
        receipt_sequence_valid = False
        try:
            transition_receipts = validate_legacy_transition_prefix(ledger.events)
            parsed_receipts = tuple(
                TransitionResult.from_dict(receipt) for receipt in receipts
            )
            expected_edges = tuple(
                f"{receipt.prior_state.value}->{receipt.current_state.value}"
                for receipt in parsed_receipts
            )
            receipt_sequence_valid = (
                isinstance(receipts, list)
                and tuple(receipts)
                == tuple(receipt.to_dict() for receipt in parsed_receipts)
                and parsed_receipts == transition_receipts
                and expected_edges
                == tuple(manifest.get("completed_transitions", ()))
                and StateController(
                    initial_state=recovery.derived_state or MacroState.CALIBRATE,
                    artifact_registry=self._registry(run_id),
                    prior_receipts=parsed_receipts,
                ).current_state
                == parse_state(recovery.derived_state or MacroState.CALIBRATE)
            )
        except Exception:
            receipt_sequence_valid = False
        evaluation_receipts_valid = True
        for stored in manifest.get("evaluator_decisions", {}).values():
            try:
                if not isinstance(stored, Mapping):
                    raise ValueError("stored evaluator receipt is not an object")
                _evaluation_from_legacy_receipt(stored)
            except (KeyError, TypeError, ValueError):
                evaluation_receipts_valid = False
                break
        ledger_evaluations: dict[str, dict[str, Any]] = {}
        if evaluation_receipts_valid:
            for event in ledger.events:
                keys = event.get("metadata", {}).get("evaluator_keys", [])
                outputs = event.get("evaluator_outputs", [])
                if (
                    not isinstance(keys, list)
                    or not isinstance(outputs, list)
                    or len(keys) != len(outputs)
                ):
                    evaluation_receipts_valid = False
                    break
                for key, output in zip(keys, outputs, strict=True):
                    if not isinstance(key, str) or not isinstance(output, dict):
                        evaluation_receipts_valid = False
                        break
                    prior = ledger_evaluations.get(key)
                    if prior is not None and prior != output:
                        evaluation_receipts_valid = False
                        break
                    ledger_evaluations[key] = output
                if not evaluation_receipts_valid:
                    break
        if ledger_evaluations != manifest.get("evaluator_decisions"):
            evaluation_receipts_valid = False
        live_custody_valid = self._validate_live_custody(manifest)
        architecture_control_valid = (
            self._validate_live_architecture_control(manifest)
        )
        custody_boundary_valid = (
            live_custody_valid or architecture_control_valid
        )
        live_inventory_valid = self._validate_live_inventories(manifest)
        run_intent_valid = False
        try:
            run_intent = self._json_artifact_payload(manifest, "run_intent")
            run_intent_valid = (
                run_intent.get("kind") == "FROZEN_RUN_INTENT"
                and run_intent.get("mode") == manifest.get("mode")
                and run_intent.get("synthetic_scenario")
                == manifest.get("synthetic_scenario")
                and run_intent.get("package_kind") == manifest.get("package_kind")
                and ledger_artifact_projection.get("run_intent")
                == manifest.get("artifacts", {}).get("run_intent", {}).get("sha256")
            )
        except Exception:
            run_intent_valid = False
        resource_runtime_valid = (
            isinstance(manifest.get("resource_runtime_state"), Mapping)
            and isinstance(manifest.get("resource_runtime_artifact"), str)
            and "resource_runtime_initial" in ledger_artifact_projection
        )
        if resource_runtime_valid:
            try:
                self._resource_controller(manifest)
            except OrchestrationError:
                resource_runtime_valid = False
        rollback_authority_stop = False
        if (
            not resource_runtime_valid
            and manifest.get("terminal_state") == "STOP_SECURITY"
        ):
            try:
                stop_report = self._json_artifact_payload(
                    manifest, "terminal_report"
                )
                resource_runtime_valid = (
                    stop_report.get("terminal_state") == "STOP_SECURITY"
                    and stop_report.get("evidence", {}).get("resource_authority")
                    == "ROLLBACK_OR_STALE_PROJECTION"
                )
                rollback_authority_stop = resource_runtime_valid
            except Exception:
                resource_runtime_valid = False
        if rollback_authority_stop and not custody_boundary_valid:
            # The external journal's survival is the rollback evidence.  The
            # typed STOP_SECURITY report makes that fail-closed condition the
            # expected verified outcome rather than authorizing claims.
            custody_boundary_valid = True
        final_package_valid = True
        if manifest.get("terminal_state") == "READY_FOR_HUMAN_REVIEW":
            try:
                checked_package = package_run(self.root, run_id).to_dict()
                final_package_valid = checked_package == manifest.get("package")
            except Exception:
                final_package_valid = False
        status_passed = all(
            (
                ledger.valid,
                external_checkpoint_valid,
                artifacts.valid,
                registry.valid,
                registry_matches_manifest,
                registry_closure_valid,
                ledger_projection_valid,
                contract_ok,
                state_matches_ledger,
                terminal_projection_valid,
                manifest_matches_ledger,
                recovery_safe,
                ledger_sequence_valid,
                provenance_valid,
                receipt_sequence_valid,
                evaluation_receipts_valid,
                custody_boundary_valid,
                live_inventory_valid,
                run_intent_valid,
                resource_runtime_valid,
                resource_authority_history_valid,
                final_package_valid,
            )
        )
        result = {
            "schema_version": SCHEMA_VERSION,
            "kind": "RUN_VERIFICATION",
            "run_id": run_id,
            "status": "PASS" if status_passed else "FAIL",
            "ledger": {
                "implementation": "EventLedger",
                "valid": ledger.valid,
                "event_count": ledger.event_count,
                "head_hash": ledger.head_hash,
                "error": ledger.error,
                "transition_sequence_valid": ledger_sequence_valid,
                "provenance_valid": provenance_valid,
            },
            "artifacts": {
                "valid": artifacts.valid,
                "records_validated": artifacts.records_validated,
                "issues": [asdict(item) for item in artifacts.issues],
                "registry_valid": registry.valid,
                "registry_records": registry.count,
                "registry_errors": list(registry.errors),
                "registry_matches_manifest": registry_matches_manifest,
                "registry_closure_valid": registry_closure_valid,
                "ledger_projection_valid": ledger_projection_valid,
            },
            "state_contract_valid": contract_ok,
            "state_matches_ledger": state_matches_ledger,
            "terminal_projection_valid": terminal_projection_valid,
            "manifest_matches_ledger": manifest_matches_ledger,
            "external_checkpoint_valid": external_checkpoint_valid,
            "typed_receipts_valid": receipt_sequence_valid,
            "evaluator_receipts_valid": evaluation_receipts_valid,
            "live_custody_valid": live_custody_valid,
            "architecture_control_valid": architecture_control_valid,
            "custody_boundary_valid": custody_boundary_valid,
            "live_inventory_valid": live_inventory_valid,
            "run_intent_binding_valid": run_intent_valid,
            "resource_runtime_binding_valid": resource_runtime_valid,
            "resource_authority_history_valid": resource_authority_history_valid,
            "final_package_binding_valid": final_package_valid,
            "recovery": recovery.to_dict(),
            "external_network_used": False,
        }
        return result

    def _handler_audit(self, manifest: dict[str, Any]) -> None:
        verification = self.verify(str(manifest["run_id"]))
        if verification["status"] != "PASS":
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "run verification failed before audit",
                evidence={"verification": verification},
            )
            return
        reproduction = reproduce_architecture_control_run(
            self.root, str(manifest["run_id"]), timestamp=manifest["created_at"]
        )
        reproduction_payload = reproduction.to_dict()
        try:
            reproduction_manifest_bytes = read_confined_bytes(
                self.root,
                reproduction.manifest_path,
                reject_hardlinks=True,
                max_bytes=16 * 1024 * 1024,
            )
            reproduction_result_bytes = read_confined_bytes(
                self.root,
                reproduction.result_path,
                reject_hardlinks=True,
                max_bytes=16 * 1024 * 1024,
            )
        except PathSecurityError as exc:
            raise OrchestrationError("reproduction packet cannot be frozen") from exc
        if reproduction_manifest_bytes is None or reproduction_result_bytes is None:
            raise OrchestrationError("reproduction packet disappeared")
        reproduction_manifest_record = self._artifact_from_file(
            manifest,
            "reproduction_manifest",
            self.root / reproduction.manifest_path,
            creator=Role.REPRODUCTION_VERIFIER.value,
            mime_type="application/json",
            parents=(manifest["artifacts"]["machine_results"]["sha256"],),
            max_bytes=16 * 1024 * 1024,
            expected_bytes=reproduction_manifest_bytes,
        )
        reproduction_result_record = self._artifact_from_file(
            manifest,
            "reproduction_result",
            self.root / reproduction.result_path,
            creator=Role.REPRODUCTION_VERIFIER.value,
            mime_type="application/json",
            parents=(reproduction_manifest_record["sha256"],),
            max_bytes=16 * 1024 * 1024,
            expected_bytes=reproduction_result_bytes,
        )
        reproduction_payload.update(
            {
                "manifest_sha256": _sha256(reproduction_manifest_bytes),
                "manifest_record_hash": reproduction_manifest_record[
                    "registry_record_hash"
                ],
                "result_sha256": _sha256(reproduction_result_bytes),
                "result_record_hash": reproduction_result_record[
                    "registry_record_hash"
                ],
            }
        )
        manifest["reproduction"] = reproduction_payload
        self._artifact(
            manifest,
            "reproduction_report",
            reproduction_payload,
            creator=Role.REPRODUCTION_VERIFIER.value,
            parents=(
                manifest["artifacts"]["machine_results"]["sha256"],
                reproduction_manifest_record["sha256"],
                reproduction_result_record["sha256"],
            ),
        )
        verify_frozen_architecture_control_reproduction(
            self.root, str(manifest["run_id"]), reproduction_payload
        )
        protocol = self._json_artifact_payload(manifest, "frozen_protocol")
        benchmark = self._json_artifact_payload(manifest, "workflow_benchmark")
        custody = self._json_artifact_payload(manifest, "custody_record")
        results = self._json_artifact_payload(manifest, "machine_results")
        claim_graph = self._json_artifact_payload(manifest, "claim_graph")
        graph_payload = claim_graph.get("graph")
        live_claims_valid = False
        try:
            custody_valid = self._validate_live_custody(manifest)
            if not isinstance(graph_payload, dict):
                raise OrchestrationError("claim graph payload is malformed")
            live_graph = ClaimEvidenceGraph.from_dict(
                graph_payload,
                evidence_resolver=artifact_registry_resolver(
                    self._registry(str(manifest["run_id"])),
                    resolver_id="run-artifact-registry",
                ),
            )
            for claim in live_graph.claims:
                live_graph.verify_claim(
                    claim.claim_id,
                    verifier_id="claim-verifier-context-v1",
                    verifier_role=Role.CLAIM_VERIFIER,
                    confirmatory_evidence_valid=custody_valid,
                    raise_on_rejection=True,
                )
            live_claims_valid = bool(
                live_graph.writer_view(
                    include_nonscientific=True,
                    confirmatory_evidence_valid=custody_valid,
                )
            )
        except Exception:
            live_claims_valid = False
        live_custody_scientific = self._validate_live_custody(manifest)
        architecture_control_exercised = (
            self._validate_live_architecture_control(manifest)
            and not live_custody_scientific
            and custody.get("evidence_class") == "ARCHITECTURE_CONTROL"
            and custody.get("execution_kind")
            == "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
            and custody.get("scientific_evidence") is False
            and custody.get("confirmatory_claims_valid") is False
            and custody.get("authorized_access_count") == 1
            and results.get("evidence_class") == "ARCHITECTURE_CONTROL"
            and results.get("scientific_evidence") is False
        )
        evidence_checks = {
            "R0": verification["status"] == "PASS",
            "R1": protocol.get("frozen") is True
            and manifest["evaluator_decisions"].get("E2:PROTOCOL", {}).get("decision") == "PASS",
            "R2": results.get("tuned_after_reveal") is False
            and manifest["evaluator_decisions"].get("E2:CONFIRM", {}).get("decision") == "PASS",
            "R3": live_custody_scientific
            and custody.get("confirmatory_claims_valid") is True
            and custody.get("authorized_access_count") == 1,
            "R4": results.get("primary_estimate") == 1.0
            and results.get("output_hashes", {}).get("result_core") is not None,
            "R5": benchmark.get("passed") is True,
            "R6": live_claims_valid and bool(claim_graph.get("writer_view")),
            # A deterministic architecture-control replay is useful for the
            # review-only demo but is not scientific R7 authority.
            "R7": False,
        }
        architecture_replay_exercised = (
            architecture_control_exercised
            and reproduction.status == ARCHITECTURE_CONTROL_REPLAY_STATUS
            and reproduction.absolute_difference <= reproduction.tolerance
        )
        manifest["r_checks"] = {
            key: (
                "PASS"
                if passed
                else "UNTESTED"
                if key in {"R3", "R7"} and architecture_replay_exercised
                else "FAIL"
            )
            for key, passed in evidence_checks.items()
        }
        verification["scientific_checks"] = {
            key: {
                "status": manifest["r_checks"][key],
                "evidence_derived": True,
            }
            for key in sorted(evidence_checks)
        }
        verification["reproduction"] = reproduction.to_dict()
        if (
            not architecture_replay_exercised
            or any(
                not passed
                for key, passed in evidence_checks.items()
                if key not in {"R3", "R7"}
            )
        ):
            self._queue_terminal(
                manifest,
                "STOP_SCIENTIFIC_INVALIDITY",
                "one or more internal demo controls failed",
                evidence={"r_checks": dict(manifest["r_checks"])},
            )
            return
        self._artifact(manifest, "audit_report", verification, creator=Role.ORCHESTRATOR.value)
        reviewed = (
            "frozen_protocol",
            "machine_results",
            "claim_graph",
            "demo_paper",
            "audit_report",
            "reproduction_report",
        )
        e2_payload = {"kind": "E2_SCIENTIFIC_REVIEW", "evaluator_class": "E2", "authority": Role.SCIENTIFIC_REVIEWER.value, "producer_role": Role.PAPER_WRITER.value, "decision": "PASS", "critical_objection": False, "reviewed_artifact_hashes": [manifest["artifacts"][name]["sha256"] for name in reviewed], "r_checks": dict(manifest["r_checks"]), "methodological_validity": "bounded non-evidentiary architecture controls exercised; scientific R3/R7 remain UNTESTED", "limitations_preserved": True, "human_independence_claimed": False, "evidence_class": "ARCHITECTURE_CONTROL", "scientific_evidence": False, "publication_eligible": False}
        self._artifact(manifest, "e2_review", e2_payload, creator=Role.SCIENTIFIC_REVIEWER.value)
        e3_payload = {"kind": "E3_ADVERSARIAL_REPRODUCTION_REVIEW", "evaluator_class": "E3", "authority": Role.ADVERSARIAL_REVIEWER.value, "producer_role": Role.PAPER_WRITER.value, "decision": "PASS", "critical_objection": False, "reviewed_artifact_hashes": [manifest["artifacts"][name]["sha256"] for name in reviewed], "reproduction_id": reproduction.reproduction_id, "reproduction_result_path": reproduction.result_path, "reproduction_source_result_sha256": reproduction.source_result_sha256, "numeric_comparison": {"expected": reproduction.expected, "observed": reproduction.observed, "absolute_difference": reproduction.absolute_difference, "tolerance": reproduction.tolerance, "passed": architecture_replay_exercised, "scientific_reproduction_passed": False, "replay_scope": "REVIEW_ONLY_ARCHITECTURE_CONTROL"}, "searched": ["leakage", "contamination", "p-hacking", "multiplicity", "invalid independence", "gaming", "contradictions", "provenance gaps"], "r_checks": dict(manifest["r_checks"]), "human_independence_claimed": False, "evidence_class": "ARCHITECTURE_CONTROL", "scientific_evidence": False, "publication_eligible": False}
        self._artifact(manifest, "e3_review", e3_payload, creator=Role.ADVERSARIAL_REVIEWER.value)
        audit_names = ("audit_report", "e2_review", "e3_review")
        self._evaluate(manifest, "E2:AUDIT", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, audit_names, tuple(RCheck), producer=Role.PAPER_WRITER)
        self._evaluate(manifest, "E3:AUDIT", EvaluatorClass.E3, Role.ADVERSARIAL_REVIEWER, audit_names, tuple(RCheck), producer=Role.PAPER_WRITER)
        descriptive_evaluations = [
                Evaluation(
                    EvaluatorClass.E0,
                    Role.ORCHESTRATOR,
                    Decision.PASS,
                    (manifest["artifacts"]["audit_report"]["sha256"],),
                    "deterministic internal R0-R4 architecture-control validation",
                    (RCheck.R0, RCheck.R1, RCheck.R2, RCheck.R3, RCheck.R4),
                ),
                Evaluation(
                    EvaluatorClass.E2,
                    Role.SCIENTIFIC_REVIEWER,
                    Decision.PASS,
                    (manifest["artifacts"]["e2_review"]["sha256"],),
                    "same-process role-separated non-evidentiary R1-R2/R4-R6 checks",
                    (RCheck.R1, RCheck.R2, RCheck.R4, RCheck.R5, RCheck.R6),
                    producer_role=Role.PAPER_WRITER,
                ),
                Evaluation(
                    EvaluatorClass.E3,
                    Role.ADVERSARIAL_REVIEWER,
                    Decision.PASS,
                    (manifest["artifacts"]["e3_review"]["sha256"],),
                    "adversarial review of architecture-control R3/R5-R7 boundaries; R3/R7 remain UNTESTED scientifically",
                    (RCheck.R3, RCheck.R5, RCheck.R6, RCheck.R7),
                    producer_role=Role.PAPER_WRITER,
                ),
            ]
        # These local rules only decide whether the bounded demo can be
        # packaged.  They are deliberately not paper-readiness authority.
        score_rules = {
            "question": evidence_checks["R1"],
            "novelty_evidence": manifest.get("novelty") == "NOVELTY_UNVERIFIED",
            "falsifiability": evidence_checks["R1"],
            "methodological_validity": all(evidence_checks[key] for key in ("R1", "R2", "R4")) and architecture_control_exercised,
            "baseline_fairness": evidence_checks["R2"],
            "experimental_design": all(evidence_checks[key] for key in ("R1", "R5")) and architecture_control_exercised,
            "statistical_validity": evidence_checks["R4"],
            "ablations_robustness": evidence_checks["R5"],
            "negative_controls": evidence_checks["R5"],
            "reproducibility": architecture_replay_exercised,
            "claim_evidence_alignment": evidence_checks["R6"],
            "writing_clarity": evidence_checks["R6"],
            "limitations": evidence_checks["R6"],
            "artifact_quality": evidence_checks["R0"],
        }
        rubric_bytes = read_confined_bytes(
            self.root,
            "configs/paper_readiness_rubric.json",
            reject_hardlinks=True,
            max_bytes=1024 * 1024,
        )
        if rubric_bytes is None:
            raise OrchestrationError("readiness rubric disappeared")
        run_id = str(manifest["run_id"])
        registry = self._registry(run_id)
        ledger = EventLedger(
            self.root,
            Path("runs") / run_id / "events.jsonl",
        )
        rubric_record = register_frozen_readiness_rubric(
            registry,
            rubric_bytes,
        )
        self._bind_registered_control_artifact(
            manifest,
            "paper_readiness_rubric",
            rubric_record,
        )
        rubric_events = tuple(
            event
            for event in ledger.validate().events
            if rubric_record.sha256 in event.artifact_hashes
        )
        if not rubric_events:
            rubric_event = ledger.record(
                run_id=run_id,
                event_id=f"event-{int(manifest['event_count']) + 1:04d}",
                timestamp=_utc_now(),
                actor_role=Role.PROTOCOL_DESIGNER,
                state_before=MacroState.AUDIT,
                requested_state_after=MacroState.AUDIT,
                artifact_hashes=(rubric_record.sha256,),
                code_version=str(manifest["code_fingerprint"]),
                configuration_hash=str(manifest["configuration_sha256"]),
                dataset_identifiers=manifest["fixture_identifiers"],
                random_seeds=manifest["random_seeds"],
                reason="freeze exact paper-readiness rubric before R-check authority",
                event_type="CHECKPOINT",
                metadata={
                    "schema_version": SCHEMA_VERSION,
                    "artifact_types": [rubric_record.logical_type],
                    "artifact_record_hashes": [str(rubric_record.record_hash)],
                    "artifact_descriptors": [
                        {
                            "logical_type": rubric_record.logical_type,
                            "sha256": rubric_record.sha256,
                            "registry_record_hash": str(rubric_record.record_hash),
                            "parent_artifacts": [],
                            "parent_record_hashes": [],
                        }
                    ],
                },
            )
            manifest["event_count"] = int(manifest["event_count"]) + 1
            manifest["ledger_head_hash"] = rubric_event.event_hash
        elif len(rubric_events) != 1:
            raise OrchestrationError(
                "readiness rubric must have one exact ledger admission"
            )
        authority_records = tuple(
            register_r_check_authority(
                registry,
                ledger,
                run_id=run_id,
                r_check=check,
                evaluator_class=evaluator_class,
            )
            for check in RCheck
            for evaluator_class in sorted(
                REQUIRED_R_AUTHORITIES[check],
                key=lambda value: value.value,
            )
        )
        for authority_record in authority_records:
            authority_value = safe_json_loads(
                registry.get_bytes(authority_record.sha256)
            )
            if not isinstance(authority_value, Mapping):
                raise OrchestrationError("R-check authority is not structured")
            self._bind_registered_control_artifact(
                manifest,
                (
                    "r_check_authority."
                    f"{authority_value['r_check']}.{authority_value['evaluator_class']}"
                ),
                authority_record,
            )
        authority_bundle = register_r_check_authority_bundle(
            registry,
            ledger,
            run_id=run_id,
            authority_artifact_sha256s=(
                item.sha256 for item in authority_records
            ),
            rubric_artifact_sha256=rubric_record.sha256,
        )
        self._bind_registered_control_artifact(
            manifest,
            "r_check_authority_bundle",
            authority_bundle,
        )
        summary = AuditSummary(
            descriptive_evaluations,
            authority_bundle.sha256,
        )
        readiness = evaluate_readiness(
            summary,
            registry=registry,
            ledger=ledger,
            run_id=run_id,
        )
        internal_demo_controls = all(score_rules.values())
        if not internal_demo_controls:
            self._queue_terminal(
                manifest,
                "INCONCLUSIVE",
                "internal demo readiness controls did not all pass",
                evidence={
                    "readiness_score": readiness.score,
                    "blockers": list(readiness.blockers),
                    "score_rules": score_rules,
                },
            )
            return
        readiness_payload = {
            "kind": "PAPER_READINESS_EVALUATION",
            "rubric_sha256": readiness.rubric_sha256,
            "authority_bundle_sha256": readiness.authority_bundle_sha256,
            "authority_scope": readiness.authority_scope.value,
            "score": readiness.score,
            "category_weighted_scores": readiness.category_scores,
            "category_statuses": readiness.category_statuses,
            "non_authoritative_deterministic_score_rules": score_rules,
            "passed_governance_candidate_gate": readiness.passed,
            "passed_internal_demo_threshold": internal_demo_controls,
            "blockers": list(readiness.blockers),
            "maximum_label": readiness.maximum_label,
            "novelty": "NOVELTY_UNVERIFIED",
            "submission_ready": False,
            "e4_present": False,
        }
        self._artifact(
            manifest,
            "readiness_report",
            readiness_payload,
            creator=Role.SCIENTIFIC_REVIEWER.value,
            parents=(
                manifest["artifacts"]["audit_report"]["sha256"],
                authority_bundle.sha256,
            ),
        )
        audit_names = (
            "audit_report",
            "reproduction_report",
            "e2_review",
            "e3_review",
            "readiness_report",
        )
        self._evaluate(
            manifest,
            "E0:AUDIT",
            EvaluatorClass.E0,
            Role.ORCHESTRATOR,
            audit_names,
            tuple(RCheck),
            producer=Role.PAPER_WRITER,
        )
        # Rebind the independent receipts to the full canonical AUDIT bundle,
        # including the frozen readiness and reproduction artifacts.
        self._evaluate(manifest, "E2:AUDIT", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, audit_names, tuple(RCheck), producer=Role.PAPER_WRITER)
        self._evaluate(manifest, "E3:AUDIT", EvaluatorClass.E3, Role.ADVERSARIAL_REVIEWER, audit_names, tuple(RCheck), producer=Role.PAPER_WRITER)

    @_project_command
    def reproduce(self, run_id: str) -> dict[str, Any]:
        manifest = self.load_manifest(run_id)
        self._assert_no_newer_external_checkpoint(manifest)
        if (
            manifest.get("current_state")
            in {"STOP_SECURITY", "STOP_SCIENTIFIC_INVALIDITY"}
            or manifest.get("terminal_state")
            in {"STOP_SECURITY", "STOP_SCIENTIFIC_INVALIDITY"}
        ):
            raise OrchestrationError("terminal stop forbids reproduction work")
        if self.verify(run_id).get("status") != "PASS":
            raise OrchestrationError(
                "run verification failed before frozen reproduction replay"
            )
        existing = manifest.get("reproduction")
        if existing is not None:
            if not isinstance(existing, dict):
                raise OrchestrationError("frozen reproduction record differs")
            frozen_report = self._json_artifact_payload(
                manifest, "reproduction_report"
            )
            if frozen_report != existing:
                raise OrchestrationError("registered reproduction report differs")
            if existing.get("status") == ARCHITECTURE_CONTROL_REPLAY_STATUS:
                verify_frozen_architecture_control_reproduction(
                    self.root, run_id, existing
                )
            else:
                verify_frozen_reproduction(self.root, run_id, existing)
            return dict(existing)
        machine_results = self._json_artifact_payload(manifest, "machine_results")
        if machine_results.get("evidence_class") == "ARCHITECTURE_CONTROL":
            result = reproduce_architecture_control_run(
                self.root, run_id, timestamp=manifest["created_at"]
            )
        else:
            result = reproduce_run(
                self.root, run_id, timestamp=manifest["created_at"]
            )
        value = result.to_dict()
        manifest["reproduction"] = value
        self._save_manifest(manifest)
        return value

    def _handler_release(self, manifest: dict[str, Any]) -> None:
        readiness = self._json_artifact_payload(manifest, "readiness_report")
        bundle_sha256 = readiness.get("authority_bundle_sha256")
        if not isinstance(bundle_sha256, str):
            raise OrchestrationError("readiness report lacks its authority bundle")
        run_id = str(manifest["run_id"])
        registry = self._registry(run_id)
        ledger = EventLedger(
            self.root,
            Path("runs") / run_id / "events.jsonl",
        )
        try:
            resolved = evaluate_readiness(
                AuditSummary([], bundle_sha256),
                registry=registry,
                ledger=ledger,
                run_id=run_id,
            )
        except Exception as exc:
            raise OrchestrationError(
                "frozen paper-readiness authority failed fresh resolution"
            ) from exc
        if (
            readiness.get("rubric_sha256") != resolved.rubric_sha256
            or readiness.get("authority_scope") != resolved.authority_scope.value
            or readiness.get("score") is not None
            or readiness.get("category_weighted_scores")
            != resolved.category_scores
            or readiness.get("category_statuses")
            != resolved.category_statuses
            or readiness.get("blockers") != list(resolved.blockers)
            or readiness.get("maximum_label") != resolved.maximum_label
            or readiness.get("passed_governance_candidate_gate") is not False
            or resolved.passed is not False
            or resolved.maximum_label != "INCONCLUSIVE"
            or readiness.get("submission_ready") is not False
            or readiness.get("e4_present") is not False
            or readiness.get("passed_internal_demo_threshold") is not True
        ):
            raise OrchestrationError(
                "legacy demo release differs from conservative readiness authority"
            )
        if manifest.get("reproduction") is None:
            raise OrchestrationError("AUDIT must freeze reproduction before RELEASE")
        self._save_manifest(manifest)
        package = package_run(self.root, str(manifest["run_id"]))
        package_payload = package.to_dict()
        self._artifact(manifest, "release_candidate", package_payload, creator=Role.RELEASE_PACKAGER.value, parents=tuple(record["sha256"] for record in manifest["artifacts"].values()))
        manifest["package"] = package_payload
        self._evaluate(manifest, "E0:RELEASE", EvaluatorClass.E0, Role.ORCHESTRATOR, ("release_candidate",), (RCheck.R7,), producer=Role.RELEASE_PACKAGER)
        self._evaluate(manifest, "E2:RELEASE", EvaluatorClass.E2, Role.SCIENTIFIC_REVIEWER, ("release_candidate",), (RCheck.R7,), producer=Role.RELEASE_PACKAGER)
        self._evaluate(manifest, "E3:RELEASE", EvaluatorClass.E3, Role.ADVERSARIAL_REVIEWER, ("release_candidate",), (RCheck.R7,), producer=Role.RELEASE_PACKAGER)

    _HANDLERS: dict[str, Callable[["ScientistOneOrchestrator", dict[str, Any]], None]] = {
        "CALIBRATE": _handler_calibrate,
        "CHARTER": _handler_charter,
        "GROUND": _handler_ground,
        "PROTOCOL": _handler_protocol,
        "PREFLIGHT": _handler_preflight,
        "IDEATE": _handler_ideate,
        "DISCOVER": _handler_discover,
        "CANDIDATE": _handler_candidate,
        "CONFIRM": _handler_confirm,
        "CLAIMS": _handler_claims,
        "WRITE": _handler_write,
        "AUDIT": _handler_audit,
        "RELEASE": _handler_release,
    }

    def _typed_transition(
        self,
        manifest: dict[str, Any],
        contract: TransitionContract,
        *,
        evaluator_key_map: Mapping[EvaluatorClass, str] | None = None,
    ) -> dict[str, Any]:
        """Revalidate the orchestration decision through the foundation controller."""

        source = contract.source
        destination = contract.destination
        required_records = [
            manifest["artifacts"][name]
            for name in sorted(contract.required_artifact_types)
        ]
        registry = self._registry(str(manifest["run_id"]))
        registry_records = []
        for record in required_records:
            metadata = registry.get_metadata(record["sha256"])
            if (
                metadata.logical_type != record["logical_type"]
                or metadata.schema_version != record["schema_version"]
                or metadata.size != record["size"]
                or metadata.frozen is not True
                or metadata.path != record.get("registry_path")
                or metadata.metadata_path != record.get("registry_metadata_path")
                or metadata.record_hash != record.get("registry_record_hash")
            ):
                raise OrchestrationError("manifest artifact does not match its registry record")
            registry_records.append(metadata)
        artifact_refs = tuple(record.to_ref() for record in registry_records)
        evaluation_values: list[Evaluation] = []
        for evaluator_class in sorted(contract.required_evaluators, key=lambda item: item.value):
            key = (
                evaluator_key_map[evaluator_class]
                if evaluator_key_map is not None
                else _evaluation_key(source.value, evaluator_class)
            )
            stored = manifest["evaluator_decisions"].get(key)
            if not isinstance(stored, dict):
                raise OrchestrationError(f"missing stored evaluator receipt: {key}")
            try:
                evaluation = _evaluation_from_legacy_receipt(stored)
            except (KeyError, TypeError, ValueError) as exc:
                raise OrchestrationError(f"malformed stored evaluator receipt: {key}") from exc
            evaluation_values.append(evaluation)
        expected_calibration_hash: str | None = None
        calibration_forward = (
            source is MacroState.CALIBRATE
            and destination is MacroState.CHARTER
        )
        if calibration_forward:
            expected_calibration_hash = assert_calibrated(run_calibration()).report_sha256

        def validate_calibration(request: TransitionRequest) -> bool:
            if not calibration_forward:
                return True
            return (
                request.metadata.get("canonical_calibration_report_sha256")
                == expected_calibration_hash
                and request.metadata.get("mandatory_calibration_passed") is True
            )

        approver = sorted(contract.allowed_approvers, key=lambda item: item.value)[0]
        request = TransitionRequest(
            run_id=str(manifest["run_id"]),
            from_state=source,
            to_state=destination,
            requester=Role.ORCHESTRATOR,
            approver=approver,
            artifacts=artifact_refs,
            evaluations=tuple(evaluation_values),
            idempotency_key=f"{manifest['run_id']}:{source.value}:{destination.value}",
            reason="explicit artifact and evaluator contract satisfied",
            metadata={
                "canonical_calibration_report_sha256": expected_calibration_hash,
                "mandatory_calibration_passed": not calibration_forward
                or self._json_artifact_payload(manifest, "calibration_report").get("mandatory_passed") is True,
            },
        )
        def load_reference(reference: ArtifactRef) -> bytes:
            try:
                return registry.get_bytes(reference.sha256)
            except Exception as exc:
                raise OrchestrationError("typed transition artifact is absent or corrupt") from exc

        semantic_validators: dict[str, Callable[[ArtifactRef], bool]] = {}
        if calibration_forward:
            def validate_report(reference: ArtifactRef) -> bool:
                try:
                    observed = safe_json_loads(load_reference(reference))
                    expected = assert_calibrated(run_calibration()).to_dict()
                except (ValueError, OrchestrationError):
                    return False
                # The command wrapper adds status/provider disclosure fields;
                # the canonical scientific report itself must remain identical.
                observed.pop("status", None)
                observed.pop("external_integrations_used", None)
                return observed == expected
            semantic_validators["calibration_report"] = validate_report
        result = StateController(
            initial_state=source,
            contracts=(contract,),
            artifact_registry=registry,
            semantic_validators=semantic_validators,
        ).transition(request)
        return result.to_dict()

    @_project_command
    def advance_once(self, run_id: str) -> dict[str, Any]:
        manifest = self.load_manifest(run_id)
        self._assert_no_newer_external_checkpoint(manifest)
        pilot_disposition = self._pilot_operation_disposition(manifest)
        if pilot_disposition is not None:
            return pilot_disposition
        if manifest.get("terminal_state"):
            return self.status(run_id)
        refusal = self._resource_admission_refusal(manifest)
        if refusal is not None:
            return self._admission_block_status(manifest, refusal)
        pending = self._pilot_evaluation_context(manifest)
        try:
            if pending is None:
                self._resource_controller(manifest)
        except OrchestrationError as exc:
            if manifest.get("current_state") not in MACRO_STATES:
                raise
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "external monotonic resource authority detected run rollback",
                evidence={
                    "resource_authority": "ROLLBACK_OR_STALE_PROJECTION",
                    "detail": str(exc),
                },
            )
            self._transition_terminal(manifest)
            return self.status(run_id)
        source = str(manifest["current_state"])
        if source not in self._HANDLERS or source not in TRANSITION_CONTRACTS:
            raise OrchestrationError(f"unknown current state: {source}")
        contract = TRANSITION_CONTRACTS[source]
        required_evaluator_keys = [
            _evaluation_key(source, evaluator)
            for evaluator in sorted(contract.required_evaluators, key=lambda item: item.value)
        ]
        stage_already_materialized = all(
            name in manifest["artifacts"] for name in contract.required_artifact_types
        ) and all(
            manifest["evaluator_decisions"].get(key, {}).get("decision") == "PASS"
            for key in required_evaluator_keys
        )
        if pending is not None:
            self._continue_pilot_evaluation(manifest, pending)
        elif not stage_already_materialized:
            handler = self._HANDLERS[source]
            try:
                handler(self, manifest)
            except _ResourceAdmissionBlocked:
                return self.status(run_id)
        if manifest.get("pending_terminal") is not None:
            self._transition_terminal(manifest)
            return self.status(run_id)
        if manifest.get("terminal_state"):
            raise OrchestrationError(
                "handler attempted an untyped terminal shortcut without evidence"
            )
        missing_artifacts = [
            name for name in contract.required_artifact_types if name not in manifest["artifacts"]
        ]
        missing_evaluators = [
            key
            for key in required_evaluator_keys
            if manifest["evaluator_decisions"].get(key, {}).get("decision") != "PASS"
        ]
        if missing_artifacts or missing_evaluators:
            raise OrchestrationError(f"transition contract incomplete: artifacts={missing_artifacts}, evaluators={missing_evaluators}")
        destination = contract.destination.value
        manifest["typed_transition_receipts"].append(self._typed_transition(manifest, contract))
        self._append_event(
            manifest,
            source,
            destination,
            f"typed {source}->{destination} contract satisfied",
            tuple(sorted(contract.required_artifact_types)),
            required_evaluator_keys,
        )
        manifest["completed_transitions"].append(f"{source}->{destination}")
        manifest["current_state"] = destination
        if destination == "READY_FOR_HUMAN_REVIEW":
            manifest["terminal_state"] = destination
            manifest["outcome"] = "COMPLETE_DEMO_ONLY"
        self._checkpoint(manifest)
        if destination == "READY_FOR_HUMAN_REVIEW":
            self._finalize_package_envelope(manifest)
        return self.status(run_id)

    def _finalize_package_envelope(self, manifest: dict[str, Any]) -> None:
        """Publish the detached final-state binding after the terminal event."""

        package = manifest.get("package")
        release_record = manifest.get("artifacts", {}).get("release_candidate")
        if not isinstance(package, dict) or not isinstance(release_record, dict):
            raise OrchestrationError("final package envelope lacks release evidence")
        if package.get("envelope_path") is not None or package.get("envelope_sha256") is not None:
            # An existing envelope must be fully revalidated, never trusted.
            package_run(self.root, str(manifest["run_id"]))
            return
        evaluators = manifest.get("evaluator_decisions", {})
        ledger = EventLedger(
            self.root,
            Path("runs") / str(manifest["run_id"]) / "events.jsonl",
        ).validate()
        if (
            not ledger.valid
            or not ledger.events
            or ledger.head_hash != manifest.get("ledger_head_hash")
        ):
            raise OrchestrationError("final envelope ledger is invalid")
        final_event = ledger.events[-1]
        registry = self._registry(str(manifest["run_id"]))
        release_metadata = registry.get_metadata(release_record["sha256"])
        try:
            release_payload = safe_json_loads(
                registry.get_bytes(release_metadata.sha256)
            )
        except Exception as exc:
            raise OrchestrationError("final release evidence is invalid") from exc
        release_event_evaluations = {
            f"{value.get('evaluator_class')}:RELEASE": safe_json_loads(
                canonical_json_bytes(value)
            )
            for value in final_event.evaluator_outputs
            if isinstance(value, Mapping)
        }
        envelope = {
            "schema_version": SCHEMA_VERSION,
            "kind": "FINAL_RELEASE_ENVELOPE",
            "run_id": manifest["run_id"],
            "archive_path": package["archive_path"],
            "archive_sha256": package["archive_sha256"],
            "release_candidate_sha256": release_record["sha256"],
            "release_candidate_record_hash": release_record["registry_record_hash"],
            "final_ledger_head_hash": manifest["ledger_head_hash"],
            "final_event_count": manifest["event_count"],
            "final_event_id": f"event-{int(manifest['event_count']):04d}",
            "release_evaluator_sha256": {
                key: evaluators[key]["evaluation_sha256"]
                for key in ("E0:RELEASE", "E2:RELEASE", "E3:RELEASE")
            },
            "terminal_state": "READY_FOR_HUMAN_REVIEW",
            "outcome": "COMPLETE_DEMO_ONLY",
            "publication_authority": "E4_HUMAN_REQUIRED",
            "bundle_role": "PRE_RELEASE_EVIDENCE_BUNDLE",
            "ledger_events": [event.to_dict() for event in ledger.events],
            "release_candidate_record": release_metadata.to_dict(),
            "release_candidate_payload": release_payload,
            "release_evaluator_receipts": {
                key: release_event_evaluations[key]
                for key in ("E0:RELEASE", "E2:RELEASE", "E3:RELEASE")
            },
        }
        data = _canonical_bytes(envelope)
        _assert_gateway_trust_root_not_serialized(
            registry,
            {"DETACHED_FINAL_RELEASE_ENVELOPE.json": data},
        )
        digest = _sha256(data)
        relative = (
            Path("artifacts")
            / "release_candidates"
            / f"{manifest['run_id']}-{digest[:20]}.final-envelope.json"
        )
        try:
            atomic_write_bytes(
                self.root,
                relative,
                data,
                immutable=True,
                create_parents=True,
            )
        except PathSecurityError as exc:
            raise OrchestrationError("final release envelope publication failed") from exc
        package["envelope_path"] = relative.as_posix()
        package["envelope_sha256"] = digest
        self._save_manifest(manifest)
        package_run(self.root, str(manifest["run_id"]))

    @_project_command
    def resume(self, run_id: str) -> dict[str, Any]:
        manifest = self.load_manifest(run_id)
        pilot_disposition = self._pilot_operation_disposition(manifest)
        if pilot_disposition is not None:
            return pilot_disposition
        if manifest.get("terminal_state") is None:
            refusal = self._resource_admission_refusal(manifest)
            if refusal is not None:
                return self._admission_block_status(manifest, refusal)
        pending = self._pilot_evaluation_context(manifest)
        if pending is not None:
            self.advance_once(run_id)
            manifest = self.load_manifest(run_id)
            if manifest.get("current_state") != "CONFIRM":
                raise OrchestrationError("evaluator continuation did not commit CONFIRM")
        recovery = self._recovery_report(manifest)
        if recovery.action.value == "STOP_SECURITY" and any(
            "checkpoint" in str(reason).lower() for reason in recovery.reasons
        ):
            # A stale ledger cannot safely receive a new terminal event: doing
            # so would create a fork colliding with the surviving immutable
            # checkpoint timeline.  Expose the typed recovery refusal through
            # this out-of-band command result and leave every authority byte
            # unchanged.
            return {
                "status": "STOP_SECURITY",
                "run_id": run_id,
                "current_state": "STOP_SECURITY",
                "terminal_state": "STOP_SECURITY",
                "outcome": "STOP_SECURITY",
                "mode": manifest.get("mode"),
                "artifact_count": len(manifest.get("artifacts", {})),
                "event_count": recovery.ledger_event_count,
                "resumable": False,
                "persisted": False,
                "authority_channel": "EXTERNAL_CHECKPOINT_RECOVERY_REFUSAL",
                "recovery": recovery.to_dict(),
            }
        if recovery.action.value == "STOP_SECURITY" and any(
            "INVALID_LEGACY_TRANSITION_AUTHORITY" in str(reason)
            for reason in recovery.reasons
        ):
            # Historical v1 receipts omitted the exact request and evaluator
            # context.  They remain inspectable evidence, but no migration may
            # synthesize the missing authority or append a new trusted edge.
            return {
                "status": "STOP_SECURITY",
                "run_id": run_id,
                "current_state": recovery.derived_state,
                "terminal_state": manifest.get("terminal_state"),
                "outcome": "STOP_SECURITY",
                "mode": manifest.get("mode"),
                "artifact_count": len(manifest.get("artifacts", {})),
                "event_count": recovery.ledger_event_count,
                "resumable": False,
                "persisted": False,
                "authority_channel": "LEGACY_V1_AUTHORITY_REFUSAL",
                "recovery": recovery.to_dict(),
            }
        if recovery.action.value in {
            "STOP_SECURITY",
            "STOP_SCIENTIFIC_INVALIDITY",
            "NEW_STUDY_REQUIRED",
        }:
            if (
                recovery.derived_state is not None
                and recovery.derived_state != manifest.get("current_state")
            ):
                manifest["current_state"] = recovery.derived_state
                manifest["event_count"] = recovery.ledger_event_count
                manifest["ledger_head_hash"] = recovery.ledger_head_hash
                self._save_manifest(manifest)
            if manifest.get("current_state") not in MACRO_STATES:
                # A persisted terminal edge is already the controlling
                # authority.  Never append another stop or consult resource/new-
                # study machinery merely because resume was invoked.
                return self.status(run_id)
            destination = (
                "STOP_SECURITY"
                if recovery.action.value == "STOP_SECURITY"
                else "STOP_SCIENTIFIC_INVALIDITY"
            )
            self._queue_terminal(
                manifest,
                destination,
                "recovery validation refused continuation",
                evidence={"recovery": recovery.to_dict()},
            )
            self._transition_terminal(manifest)
            return self.status(run_id)
        if manifest.get("terminal_state") != "STOP_SECURITY":
            try:
                self._resource_controller(manifest)
            except OrchestrationError as exc:
                if manifest.get("current_state") not in MACRO_STATES:
                    raise
                self._queue_terminal(
                    manifest,
                    "STOP_SECURITY",
                    "external monotonic resource authority detected run rollback",
                    evidence={
                        "resource_authority": "ROLLBACK_OR_STALE_PROJECTION",
                        "detail": str(exc),
                    },
                )
                self._transition_terminal(manifest)
                return self.status(run_id)
        if recovery.derived_state is not None and recovery.derived_state != manifest.get("current_state"):
            manifest["current_state"] = recovery.derived_state
            manifest["event_count"] = recovery.ledger_event_count
            manifest["ledger_head_hash"] = recovery.ledger_head_hash
            self._save_manifest(manifest)
        if recovery.action.value == "SKIP_COMPLETED" and manifest.get("terminal_state") is not None:
            package = manifest.get("package")
            if (
                manifest.get("terminal_state") == "READY_FOR_HUMAN_REVIEW"
                and isinstance(package, dict)
                and (
                    package.get("envelope_path") is None
                    or package.get("envelope_sha256") is None
                )
            ):
                self._finalize_package_envelope(manifest)
            return self.status(run_id)
        # SKIP_COMPLETED forbids replaying CONFIRM; it does not forbid the
        # downstream CLAIMS/WRITE/AUDIT/RELEASE stages. The ledger-derived
        # state below guarantees that resume never re-enters CONFIRM.
        verification = self.verify(run_id)
        if verification["status"] != "PASS":
            self._queue_terminal(
                manifest,
                "STOP_SECURITY",
                "semantic verification refused resume",
                evidence={"verification": verification},
            )
            self._transition_terminal(manifest)
            return self.status(run_id)
        while manifest.get("terminal_state") is None:
            result = self.advance_once(run_id)
            if result.get("status") == "RESOURCE_ADMISSION_BLOCKED":
                return result
            manifest = self.load_manifest(run_id)
        return self.status(run_id)

    @_project_command
    def demo(self, *, synthetic_scenario: str = "positive") -> dict[str, Any]:
        started = self.start(
            mode="synthetic_demo", synthetic_scenario=synthetic_scenario
        )
        result = self.resume(str(started["run_id"]))
        result["package"] = self.load_manifest(str(started["run_id"])).get("package")
        result["reproduction"] = self.load_manifest(str(started["run_id"])).get("reproduction")
        return result

    @_project_command
    def package(self, run_id: str) -> dict[str, Any]:
        manifest = self.load_manifest(run_id)
        self._assert_no_newer_external_checkpoint(manifest)
        if manifest.get("current_state") not in {"RELEASE", "READY_FOR_HUMAN_REVIEW"}:
            raise OrchestrationError("run must complete AUDIT before packaging")
        if manifest["current_state"] == "RELEASE":
            self.advance_once(run_id)
            manifest = self.load_manifest(run_id)
        verified = package_run(self.root, run_id).to_dict()
        if manifest.get("package") != verified:
            raise OrchestrationError("mutable package projection differs from verified evidence")
        return verified


def _locked_resource_registry_ledger_snapshot(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    run_id: str,
) -> tuple[Any, Any]:
    if (
        type(registry) is not ArtifactRegistry
        or type(ledger) is not EventLedger
        or registry.policy.root != ledger.policy.root
        or registry.base_path.name != "registry"
        or ledger.relative_path.name != "events.jsonl"
        or registry.base_path.parent != ledger.relative_path.parent
    ):
        raise OrchestrationError(
            "resource replay requires the canonical paired registry and ledger"
        )
    registry.verify_all(raise_on_error=True)
    ledger.assert_valid()
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            registry_snapshot = registry._verify_all_locked(
                registry_guard, raise_on_error=True
            )
            ledger_snapshot = ledger._validate_bytes(
                ledger._read_raw_locked(ledger_guard)
            )
            if not ledger_snapshot.valid or any(
                event.run_id != run_id for event in ledger_snapshot.events
            ):
                raise OrchestrationError("resource replay ledger is invalid")
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    return registry_snapshot, ledger_snapshot


def _resource_event_artifact_binding(
    event: LedgerEvent,
    logical_type: str,
) -> tuple[int, str] | None:
    names = event.metadata.get("artifact_types")
    record_hashes = event.metadata.get("artifact_record_hashes")
    if not isinstance(names, (list, tuple)) or not isinstance(
        record_hashes, (list, tuple)
    ):
        return None
    positions = [index for index, name in enumerate(names) if name == logical_type]
    if not positions:
        return None
    if len(positions) != 1:
        raise OrchestrationError("resource ledger artifact binding is ambiguous")
    position = positions[0]
    if position >= len(event.artifact_hashes) or position >= len(record_hashes):
        raise OrchestrationError("resource ledger artifact binding is incomplete")
    record_hash = record_hashes[position]
    if not isinstance(record_hash, str):
        raise OrchestrationError("resource ledger record hash is malformed")
    return position, record_hash


def _require_uncorrected_direct_resource_checkpoints(
    records: Sequence[Mapping[str, Any]],
    events: Sequence[LedgerEvent],
) -> tuple[tuple[int, LedgerEvent, int, str], ...]:
    """Locate each exact direct resource checkpoint and reject supersession."""

    direct_events: list[tuple[int, LedgerEvent, int, str]] = []
    for record, descriptor in zip(
        records,
        _resource_authority_descriptors_for(records),
        strict=True,
    ):
        candidates: list[tuple[int, LedgerEvent, int, str]] = []
        for index, event in enumerate(events):
            if event.metadata.get("resource_authority_checkpoint") != descriptor:
                continue
            binding = _resource_event_artifact_binding(
                event,
                str(record["logical_type"]),
            )
            if binding is None:
                continue
            position, record_hash = binding
            if (
                event.event_type == "CONFIRMATORY_STARTED"
                or event.metadata.get("execution_kind")
                == "SIMULATED_ARCHITECTURE_CONTROL_STARTED"
            ):
                continue
            if event.artifact_hashes[position] != record["state_sha256"]:
                continue
            candidates.append((index, event, position, record_hash))
        if len(candidates) != 1:
            raise OrchestrationError(
                "resource authority lacks one direct ledger checkpoint"
            )
        direct = candidates[0]
        event_index, event, _position, _record_hash = direct
        if any(
            later.event_type == "CORRECTION"
            and later.supersedes_event_id == event.event_id
            for later in events[event_index + 1 :]
        ):
            raise OrchestrationError(
                "resource authority checkpoint was superseded by correction"
            )
        direct_events.append(direct)
    return tuple(direct_events)


def _supported_builtin_resource_command(
    command: Sequence[str],
    *,
    run_id: str,
) -> bool:
    """Recognize only historical command shapes the built-in writer emitted."""

    normalized = tuple(command)
    if normalized == (
        "python3",
        "-I",
        "-S",
        "-B",
        "scripts/scientist_one_cli.py",
        "internal",
    ):
        return True
    prefix = (
        "python3",
        "-I",
        "-S",
        "-B",
        "scripts/scientist_one_cli.py",
    )
    if normalized[: len(prefix)] != prefix or len(normalized) <= len(prefix):
        return False
    operation = normalized[len(prefix)]
    arguments = normalized[len(prefix) + 1 :]
    if operation == "demo":
        return not arguments
    if operation in {"resume", "reproduce"}:
        return arguments == (run_id,)
    if operation != "start":
        return False
    if not arguments:
        return True
    if len(arguments) != 2 or arguments[0] != "--brief":
        return False
    brief = Path(arguments[1])
    return (
        bool(arguments[1])
        and len(arguments[1].encode("utf-8")) <= 4 * 1024
        and not brief.is_absolute()
        and all(part not in {"", ".", ".."} for part in brief.parts)
    )


def _require_frozen_inventory_payload(
    value: object,
    *,
    kind: str,
    required_path: str | None = None,
) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"schema_version", "kind", "entries", "aggregate_sha256"}
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("kind") != kind
        or not isinstance(value.get("entries"), list)
        or not isinstance(value.get("aggregate_sha256"), str)
    ):
        raise OrchestrationError("frozen initialization inventory is malformed")
    entries = value["entries"]
    if not entries or len(entries) > MAX_INVENTORY_ENTRIES:
        raise OrchestrationError("frozen initialization inventory exceeds its bound")
    paths: list[str] = []
    total_bytes = 0
    for item in entries:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"path", "sha256", "size"}
            or not isinstance(item.get("path"), str)
            or not item["path"]
            or Path(item["path"]).is_absolute()
            or any(part in {"", ".", ".."} for part in Path(item["path"]).parts)
            or not isinstance(item.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
            or isinstance(item.get("size"), bool)
            or not isinstance(item.get("size"), int)
            or not 0 <= item["size"] <= 4 * 1024 * 1024
        ):
            raise OrchestrationError("frozen initialization inventory entry is malformed")
        paths.append(item["path"])
        total_bytes += item["size"]
    if (
        paths != sorted(paths)
        or len(set(paths)) != len(paths)
        or total_bytes > MAX_INVENTORY_TOTAL_BYTES
        or value["aggregate_sha256"] != _sha256(_canonical_bytes(entries))
        or (
            required_path is not None
            and sum(path == required_path for path in paths) != 1
        )
    ):
        raise OrchestrationError("frozen initialization inventory binding is invalid")
    return value


def _read_resource_closure_artifact(
    registry: ArtifactRegistry,
    digest: str,
    *,
    registry_guard: Any | None,
) -> tuple[Any, bytes, object]:
    try:
        if registry_guard is None:
            registry.verify(digest, raise_on_error=True)
            record = registry.get_metadata(digest)
            raw = registry.get_bytes(digest)
        else:
            record = registry._get_metadata_locked(registry_guard, digest)
            raw = read_confined_bytes(
                registry.policy.root,
                Path(record.path),
                reject_hardlinks=True,
                max_bytes=MAX_ARTIFACT_OBJECT_BYTES,
            )
            if raw is None:
                raise OrchestrationError("resource checkpoint artifact disappeared")
        value = safe_json_loads(raw)
    except Exception as exc:
        raise OrchestrationError(
            "resource checkpoint artifact cannot be reopened"
        ) from exc
    return record, raw, value


def _require_exact_resource_checkpoint_closure(
    registry: ArtifactRegistry,
    records: Sequence[Mapping[str, Any]],
    events: Sequence[LedgerEvent],
    *,
    registry_guard: Any | None = None,
) -> tuple[tuple[int, LedgerEvent, int, str], ...]:
    """Replay exact built-in custody for the resource chain used by wall time."""

    if not records or not events:
        raise OrchestrationError("resource checkpoint closure is absent")
    logical_types = tuple(str(item.get("logical_type")) for item in records)
    has_wall_observation = (
        logical_types[-1]
        == RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
    )
    legacy_types = logical_types[:-1] if has_wall_observation else logical_types
    if legacy_types not in _LEGACY_RESOURCE_RUNTIME_STAGE_SEQUENCES:
        raise OrchestrationError("resource checkpoint stage order is not built-in")
    return _require_builtin_resource_checkpoint_records(
        registry, records, events, registry_guard=registry_guard,
    )


def _require_builtin_resource_checkpoint_records(
    registry: ArtifactRegistry,
    records: Sequence[Mapping[str, Any]],
    events: Sequence[LedgerEvent],
    *,
    registry_guard: Any | None = None,
) -> tuple[tuple[int, LedgerEvent, int, str], ...]:
    """Shared record provenance only; callers separately constrain stage order."""
    logical_types = tuple(str(item.get("logical_type")) for item in records)
    direct_events = _require_uncorrected_direct_resource_checkpoints(
        records,
        events,
    )
    if direct_events[0][0] != 0:
        raise OrchestrationError(
            "resource runtime initial authority is not bound by event zero"
        )

    loaded: list[tuple[Any, bytes, object]] = []
    for record_value in records:
        loaded.append(
            _read_resource_closure_artifact(
                registry,
                str(record_value["state_sha256"]),
                registry_guard=registry_guard,
            )
        )
    initial_record = loaded[0][0]
    if not _supported_builtin_resource_command(
        initial_record.creation_command,
        run_id=str(records[0]["state"]["run_id"]),
    ):
        raise OrchestrationError(
            "resource checkpoint creation command is not a built-in shape"
        )

    for position, (record_value, direct, stored) in enumerate(
        zip(records, direct_events, loaded, strict=True)
    ):
        event_index, event, artifact_position, record_hash = direct
        registry_record, raw, artifact_value = stored
        logical_type = logical_types[position]
        prior_sha256 = (
            str(records[position - 1]["state_sha256"]) if position else None
        )
        if logical_type == RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE:
            state = record_value.get("state")
            inventory_sha256 = (
                state.get("frozen_configuration_inventory_artifact_sha256")
                if isinstance(state, Mapping)
                else None
            )
            expected_parents = (prior_sha256, inventory_sha256)
            metadata_valid = (
                registry_record.origin
                == _RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_ORIGIN
                and registry_record.creation_command
                == _RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_COMMAND
            )
        else:
            expected_parents = () if prior_sha256 is None else (prior_sha256,)
            metadata_valid = (
                registry_record.origin == _BUILTIN_OFFLINE_ARTIFACT_ORIGIN
                and _supported_builtin_resource_command(
                    registry_record.creation_command,
                    run_id=str(records[0]["state"]["run_id"]),
                )
            )
        if (
            registry_record.sha256 != record_value.get("state_sha256")
            or registry_record.logical_type != logical_type
            or registry_record.schema_version != SCHEMA_VERSION
            or registry_record.mime_type != "application/json"
            or registry_record.creator_role is not Role.ORCHESTRATOR
            or registry_record.validation_result != "PASS"
            or not registry_record.frozen
            or registry_record.record_hash != record_hash
            or registry_record.parent_artifacts != expected_parents
            or not metadata_valid
            or artifact_value != record_value.get("state")
            or raw != _canonical_bytes(record_value["state"])
        ):
            raise OrchestrationError(
                "resource checkpoint artifact provenance is not built-in"
            )
        parent_record_hashes = [
            str(
                _read_resource_closure_artifact(
                    registry,
                    parent,
                    registry_guard=registry_guard,
                )[0].record_hash
            )
            for parent in expected_parents
        ]
        metadata = thaw_json(event.metadata)
        descriptors = metadata.get("artifact_descriptors")
        expected_descriptor = {
            "logical_type": logical_type,
            "sha256": registry_record.sha256,
            "registry_record_hash": str(registry_record.record_hash),
            "parent_artifacts": list(expected_parents),
            "parent_record_hashes": parent_record_hashes,
        }
        if (
            event.event_id != f"event-{event_index + 1:04d}"
            or event.actor_role is not Role.ORCHESTRATOR
            or event.event_type != "CHECKPOINT"
            or not isinstance(event.state_before, MacroState)
            or event.state_before != event.requested_state_after
            or not isinstance(descriptors, list)
            or artifact_position >= len(descriptors)
            or descriptors[artifact_position] != expected_descriptor
        ):
            raise OrchestrationError(
                "resource checkpoint event provenance is not built-in"
            )
        if event_index:
            initial_event = events[0]
            if (
                event.code_version != initial_event.code_version
                or event.configuration_hash != initial_event.configuration_hash
                or event.dataset_identifiers != initial_event.dataset_identifiers
                or event.random_seeds != initial_event.random_seeds
                or event.evaluator_outputs
            ):
                raise OrchestrationError(
                    "resource checkpoint event context is substituted"
                )
        if logical_type != RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE:
            stage = logical_type.removeprefix("resource_runtime_")
            if stage == "initial":
                expected_reason = "run initialized inside the offline project boundary"
            elif stage.endswith("_charge"):
                expected_reason = (
                    f"atomic {stage.removesuffix('_charge').upper()} validity charge "
                    "persisted before execution"
                )
            else:
                expected_reason = (
                    f"{stage.removesuffix('_completion').upper()} resource state "
                    "persisted after execution"
                )
            if event.reason != expected_reason:
                raise OrchestrationError(
                    "resource checkpoint event reason is substituted"
                )

    initial_event = events[0]
    initial_metadata = thaw_json(initial_event.metadata)
    if (
        initial_metadata.get("schema_version") != SCHEMA_VERSION
        or initial_metadata.get("initialization") is not True
        or initial_metadata.get("evaluator_keys") != []
        or initial_event.state_before is not MacroState.CALIBRATE
        or initial_event.requested_state_after is not MacroState.CALIBRATE
        or initial_event.prior_event_hash is not None
        or initial_event.evaluator_outputs
    ):
        raise OrchestrationError("resource initialization event is substituted")
    initialization_records: dict[str, tuple[Any, object]] = {}
    for name, kind, required_path in (
        ("frozen_source_inventory", "FROZEN_SOURCE_INVENTORY", None),
        (
            "frozen_configuration_inventory",
            "FROZEN_CONFIGURATION_INVENTORY",
            "configs/resource_limits.json",
        ),
    ):
        binding = _resource_event_artifact_binding(initial_event, name)
        if binding is None:
            raise OrchestrationError("resource initialization root is absent")
        artifact_position, record_hash = binding
        digest = initial_event.artifact_hashes[artifact_position]
        root_record, root_raw, root_value = _read_resource_closure_artifact(
            registry,
            digest,
            registry_guard=registry_guard,
        )
        validated_value = _require_frozen_inventory_payload(
            root_value,
            kind=kind,
            required_path=required_path,
        )
        root_descriptors = initial_metadata.get("artifact_descriptors")
        if (
            root_record.logical_type != name
            or root_record.schema_version != SCHEMA_VERSION
            or root_record.mime_type != "application/json"
            or root_record.origin != _BUILTIN_OFFLINE_ARTIFACT_ORIGIN
            or root_record.creator_role is not Role.ORCHESTRATOR
            or root_record.creation_command != initial_record.creation_command
            or root_record.parent_artifacts
            or root_record.validation_result != "PASS"
            or not root_record.frozen
            or root_record.record_hash != record_hash
            or root_raw != _canonical_bytes(validated_value)
            or not isinstance(root_descriptors, list)
            or artifact_position >= len(root_descriptors)
            or root_descriptors[artifact_position]
            != {
                "logical_type": name,
                "sha256": root_record.sha256,
                "registry_record_hash": str(root_record.record_hash),
                "parent_artifacts": [],
                "parent_record_hashes": [],
            }
        ):
            raise OrchestrationError(
                "resource initialization inventory provenance is substituted"
            )
        initialization_records[name] = (root_record, validated_value)
    if (
        initial_event.code_version
        != initialization_records["frozen_source_inventory"][1][
            "aggregate_sha256"
        ]
        or initial_event.configuration_hash
        != initialization_records["frozen_configuration_inventory"][1][
            "aggregate_sha256"
        ]
    ):
        raise OrchestrationError("resource initialization roots differ from event zero")
    return direct_events


def _require_resource_wall_observation_locked(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    observation_artifact_sha256: str,
    expected_run_id: str,
    project_lock_held: bool,
) -> ResourceRuntimeWallBudgetObservation:
    if not RUN_ID_PATTERN.fullmatch(expected_run_id):
        raise OrchestrationError("wall-budget replay run ID is invalid")

    def replay() -> ResourceRuntimeWallBudgetObservation:
        entry_registry, entry_ledger = _locked_resource_registry_ledger_snapshot(
            registry, ledger, expected_run_id
        )
        try:
            registry.verify(observation_artifact_sha256, raise_on_error=True)
            observation_record = registry.get_metadata(
                observation_artifact_sha256
            )
            raw = registry.get_bytes(observation_artifact_sha256)
            payload = safe_json_loads(raw)
        except Exception as exc:
            raise OrchestrationError(
                "wall-budget observation cannot be reopened"
            ) from exc
        if (
            observation_record.logical_type
            != RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
            or observation_record.schema_version != "1.0"
            or observation_record.mime_type != "application/json"
            or observation_record.origin
            != _RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_ORIGIN
            or observation_record.creator_role is not Role.ORCHESTRATOR
            or observation_record.creation_command
            != _RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_COMMAND
            or observation_record.validation_result != "PASS"
            or not observation_record.frozen
            or observation_record.record_hash is None
            or not isinstance(payload, Mapping)
            or raw != _canonical_bytes(dict(payload))
        ):
            raise OrchestrationError(
                "wall-budget observation metadata or bytes are not source-owned"
            )
        synthetic_record = {
            "logical_type": observation_record.logical_type,
            "state": dict(payload),
        }
        _runtime_state_from_authority_record(synthetic_record)
        try:
            resource_config = ResourceConfig.from_mapping(payload["resource_config"])
            runtime_state = ResourceRuntimeState.from_mapping(
                payload["runtime_state"]
            )
        except Exception as exc:
            raise OrchestrationError(
                "wall-budget observation typed payload is invalid"
            ) from exc
        if (
            payload.get("run_id") != expected_run_id
            or payload.get("kind") != "RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION"
            or payload.get("authority_scope") != "OPERATIONAL_TIME_OBSERVATION"
            or payload.get("scientific_evidence") is not False
            or payload.get("resource_config_sha256")
            != resource_config_sha256(resource_config)
            or runtime_state.config_sha256 != resource_config_sha256(resource_config)
            or runtime_state.wall_elapsed_seconds
            < resource_config.maximum_wall_clock_seconds
        ):
            raise OrchestrationError("wall-budget observation claim is invalid")
        parents = (
            str(payload["prior_resource_runtime_artifact_sha256"]),
            str(payload["frozen_configuration_inventory_artifact_sha256"]),
        )
        if observation_record.parent_artifacts != parents:
            raise OrchestrationError("wall-budget observation parents are substituted")
        try:
            inventory_record = registry.get_metadata(parents[1])
            inventory_value = safe_json_loads(registry.get_bytes(parents[1]))
        except Exception as exc:
            raise OrchestrationError(
                "wall-budget observation inventory cannot be reopened"
            ) from exc
        if (
            inventory_record.logical_type != "frozen_configuration_inventory"
            or inventory_record.creator_role is not Role.ORCHESTRATOR
            or inventory_record.record_hash
            != payload.get("frozen_configuration_inventory_record_hash")
            or inventory_record.validation_result != "PASS"
            or not inventory_record.frozen
            or not isinstance(inventory_value, Mapping)
            or inventory_value.get("kind") != "FROZEN_CONFIGURATION_INVENTORY"
        ):
            raise OrchestrationError(
                "wall-budget observation inventory binding is substituted"
            )

        records = _read_resource_authority_records(
            registry.policy.root, expected_run_id
        )
        states = _validate_monotonic_resource_states(records)
        descriptors = _resource_authority_descriptors_for(records)
        if (
            len(records) < 2
            or records[-1].get("logical_type")
            != RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
            or records[-1].get("state") != dict(payload)
            or records[-1].get("state_sha256") != observation_record.sha256
            or parents[0] != records[-2].get("state_sha256")
            or states[-1] != runtime_state
            or any(state.config_sha256 != resource_config_sha256(resource_config) for state in states)
            or sum(
                1
                for item in records
                if item.get("logical_type")
                == RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
            )
            != 1
        ):
            raise OrchestrationError(
                "wall-budget observation differs from external resource authority"
            )
        if any(
            event.metadata.get("resource_authority_chain") is not None
            for event in entry_ledger.events
        ):
            raise OrchestrationError(
                "security-stop reconciliation cannot authorize wall exhaustion"
            )

        # Reuse the legacy validator for sequence/order, then independently
        # require an exact registry record for every direct checkpoint.
        validator = object.__new__(ScientistOneOrchestrator)
        validator._validate_resource_authority_ledger(  # type: ignore[attr-defined]
            records, entry_ledger.events
        )
        direct_events = _require_exact_resource_checkpoint_closure(
            registry,
            records,
            entry_ledger.events,
        )
        for record_value, descriptor, direct in zip(
            records,
            descriptors,
            direct_events,
            strict=True,
        ):
            _index, event, position, record_hash = direct
            artifact_sha = event.artifact_hashes[position]
            try:
                registry_record = registry.get_metadata(artifact_sha)
                artifact_value = safe_json_loads(registry.get_bytes(artifact_sha))
            except Exception as exc:
                raise OrchestrationError(
                    "resource checkpoint artifact cannot be reopened"
                ) from exc
            if (
                artifact_sha != record_value["state_sha256"]
                or registry_record.logical_type != record_value["logical_type"]
                or registry_record.creator_role is not Role.ORCHESTRATOR
                or registry_record.record_hash != record_hash
                or artifact_value != record_value["state"]
            ):
                raise OrchestrationError(
                    "resource checkpoint artifact closure is substituted"
                )

        if not entry_ledger.events:
            raise OrchestrationError(
                "wall-budget observation initialization event is absent"
            )
        initial_event = entry_ledger.events[0]
        initial_inventory_binding = _resource_event_artifact_binding(
            initial_event,
            "frozen_configuration_inventory",
        )
        if (
            initial_event.metadata.get("initialization") is not True
            or initial_inventory_binding is None
        ):
            raise OrchestrationError(
                "wall-budget observation initialization inventory is absent"
            )
        inventory_position, inventory_record_hash = initial_inventory_binding
        if (
            initial_event.artifact_hashes[inventory_position] != parents[1]
            or inventory_record_hash
            != payload.get("frozen_configuration_inventory_record_hash")
            or inventory_record.sha256 != parents[1]
            or inventory_record.record_hash != inventory_record_hash
            or any(
                later.event_type == "CORRECTION"
                and later.supersedes_event_id == initial_event.event_id
                for later in entry_ledger.events[1:]
            )
        ):
            raise OrchestrationError(
                "wall-budget initialization inventory binding is substituted"
            )

        descriptor = descriptors[-1]
        observation_matches: list[tuple[int, LedgerEvent, Mapping[str, Any]]] = []
        for index, event in enumerate(entry_ledger.events):
            binding = event.metadata.get("resource_wall_budget_observation")
            if binding is not None:
                if not isinstance(binding, Mapping):
                    raise OrchestrationError(
                        "wall-budget observation event binding is malformed"
                    )
                observation_matches.append((index, event, binding))
        if len(observation_matches) != 1:
            raise OrchestrationError(
                "wall-budget observation lacks one exact ledger event"
            )
        event_index, event, binding = observation_matches[0]
        expected_binding = {
            "schema_version": RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_SCHEMA,
            "run_id": expected_run_id,
            "observation_artifact_sha256": observation_record.sha256,
            "observation_record_hash": str(observation_record.record_hash),
            "prior_resource_runtime_artifact_sha256": parents[0],
            "frozen_configuration_inventory_artifact_sha256": parents[1],
            "resource_config_sha256": resource_config_sha256(resource_config),
            "wall_elapsed_seconds": runtime_state.wall_elapsed_seconds,
            "maximum_wall_clock_seconds": resource_config.maximum_wall_clock_seconds,
            "external_authority_sequence": records[-1]["sequence"],
            "external_authority_sha256": descriptor["authority_sha256"],
            "authority_scope": "OPERATIONAL_TIME_OBSERVATION",
            "scientific_evidence": False,
        }
        artifact_binding = _resource_event_artifact_binding(
            event, RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
        )
        parent_record_hashes = [
            str(registry.get_metadata(parent).record_hash) for parent in parents
        ]
        expected_metadata = {
            "schema_version": SCHEMA_VERSION,
            "initialization": False,
            "evaluator_keys": [],
            "artifact_types": [
                RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE
            ],
            "artifact_record_hashes": [str(observation_record.record_hash)],
            "artifact_descriptors": [
                {
                    "logical_type": observation_record.logical_type,
                    "sha256": observation_record.sha256,
                    "registry_record_hash": str(observation_record.record_hash),
                    "parent_artifacts": list(parents),
                    "parent_record_hashes": parent_record_hashes,
                }
            ],
            "resource_authority_checkpoint": descriptor,
            "resource_wall_budget_observation": expected_binding,
        }
        prior_event = entry_ledger.events[event_index - 1] if event_index else None
        expected_timestamp = datetime.fromtimestamp(
            runtime_state.wall_observed_at_epoch_seconds,
            timezone.utc,
        ).isoformat().replace("+00:00", "Z")
        initial_event = entry_ledger.events[0] if entry_ledger.events else None
        if (
            dict(binding) != expected_binding
            or event.event_hash is None
            or event.actor_role is not Role.ORCHESTRATOR
            or event.event_type != "CHECKPOINT"
            or not isinstance(event.state_before, MacroState)
            or not isinstance(event.requested_state_after, MacroState)
            or any(
                isinstance(candidate.state_before, TerminalState)
                or isinstance(candidate.requested_state_after, TerminalState)
                for candidate in entry_ledger.events[: event_index + 1]
            )
            or event.state_before != event.requested_state_after
            or event.artifact_hashes != (observation_record.sha256,)
            or artifact_binding != (0, str(observation_record.record_hash))
            or event.event_id != f"event-{event_index + 1:04d}"
            or event.timestamp != expected_timestamp
            or prior_event is None
            or event.prior_event_hash != prior_event.event_hash
            or initial_event is None
            or event.code_version != initial_event.code_version
            or event.configuration_hash != initial_event.configuration_hash
            or event.dataset_identifiers != initial_event.dataset_identifiers
            or event.random_seeds != initial_event.random_seeds
            or event.evaluator_outputs
            or thaw_json(event.metadata) != expected_metadata
            or event.reason
            != "committed exhausted run wall budget from built-in clocks"
            or any(
                later.event_type == "CORRECTION"
                and later.supersedes_event_id == event.event_id
                for later in entry_ledger.events[event_index + 1 :]
            )
        ):
            raise OrchestrationError(
                "wall-budget observation event is stale or substituted"
            )
        result = ResourceRuntimeWallBudgetObservation(
            run_id=expected_run_id,
            resource_config=resource_config,
            runtime_state=runtime_state,
            frozen_configuration_inventory_artifact_sha256=parents[1],
            frozen_configuration_inventory_record_hash=str(
                inventory_record.record_hash
            ),
            prior_resource_runtime_artifact_sha256=parents[0],
            observation_artifact_sha256=observation_record.sha256,
            observation_record_hash=str(observation_record.record_hash),
            external_authority_sequence=int(records[-1]["sequence"]),
            external_authority_sha256=str(descriptor["authority_sha256"]),
            ledger_event_id=event.event_id,
            ledger_event_hash=event.event_hash,
            ledger_event_index=event_index,
        )
        final_registry, final_ledger = _locked_resource_registry_ledger_snapshot(
            registry, ledger, expected_run_id
        )
        if final_registry != entry_registry or final_ledger != entry_ledger:
            raise OrchestrationError(
                "wall-budget observation sources changed during fresh replay"
            )
        return result

    if project_lock_held:
        return replay()
    with _project_resource_execution_lock(registry.policy.root):
        return replay()


def require_resource_runtime_wall_budget_observation(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    observation_artifact_sha256: str,
    expected_run_id: str,
) -> ResourceRuntimeWallBudgetObservation:
    """Freshly replay one source-owned, ledger-bound wall-budget observation."""

    return _require_resource_wall_observation_locked(
        registry,
        ledger,
        observation_artifact_sha256=observation_artifact_sha256,
        expected_run_id=expected_run_id,
        project_lock_held=False,
    )


__all__ = [
    "MACRO_STATES",
    "TERMINAL_STATES",
    "TRANSITION_CONTRACTS",
    "OrchestrationError",
    "RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_LOGICAL_TYPE",
    "RESOURCE_RUNTIME_WALL_BUDGET_OBSERVATION_SCHEMA",
    "ResourceRuntimeWallBudgetObservation",
    "ScientistOneOrchestrator",
    "TransitionContract",
    "require_resource_runtime_wall_budget_observation",
]
