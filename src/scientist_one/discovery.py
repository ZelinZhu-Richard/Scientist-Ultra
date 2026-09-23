"""Deterministic, exploration-only scientific discovery primitives.

The discovery engine deliberately keeps every branch and every selection
decision.  Scientific failure, null results, invalid output, duplicate ideas,
and rejected promotions are records to retain, not garbage to collect.  This
module does not execute experiments and it never has access to confirmatory
resources; it only allocates an explicitly exploratory budget.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from decimal import Decimal
from enum import StrEnum
import hashlib
import math
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .artifacts import ArtifactRecord, ArtifactRegistry, MAX_ARTIFACT_PARENTS
from .errors import IntegrityError, ValidationError
from .experiments import AdaptiveExecutionPlan, OutputManifest, SeedRunStatus
from .ledger import EventLedger, LedgerEvent
from .models import freeze_json, thaw_json, validate_identifier, validate_sha256
from .roles import Role
from .security import canonical_json_bytes, safe_json_loads


MAX_DISCOVERY_BRANCHES = 10_000
MAX_DISCOVERY_ACTIONS = 100_000
MAX_DISCOVERY_SEEDS = 10_000
MAX_DISCOVERY_ABLATIONS = 1_000

# The reviewed evaluator is implemented in this module rather than loaded from
# a caller-supplied callback.  Checked proposals bind this exact source digest
# before execution through their frozen run spec and source-snapshot artifact.
_DISCOVERY_IMPLEMENTATION_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


class DiscoveryError(ValidationError):
    """A discovery request is malformed or violates branch history."""


class DiscoveryIntegrityError(IntegrityError):
    """Recorded discovery evidence is internally inconsistent."""


class DiscoveryAction(StrEnum):
    FRESH_IDEA = "FRESH_IDEA"
    INDEPENDENT_BRANCH = "INDEPENDENT_BRANCH"
    REFINE_BRANCH = "REFINE_BRANCH"
    DEBUG_BRANCH = "DEBUG_BRANCH"
    ABLATE = "ABLATE"
    RUN_CONTROL = "RUN_CONTROL"
    RUN_ROBUSTNESS = "RUN_ROBUSTNESS"
    RUN_FALSIFICATION = "RUN_FALSIFICATION"
    TERMINATE_BRANCH = "TERMINATE_BRANCH"
    PROMOTE_CANDIDATE = "PROMOTE_CANDIDATE"


class BranchStatus(StrEnum):
    ACTIVE = "ACTIVE"
    SUCCEEDED = "SUCCEEDED"
    NEGATIVE_RESULT = "NEGATIVE_RESULT"
    NULL_RESULT = "NULL_RESULT"
    FAILED = "FAILED"
    INVALID = "INVALID"
    REJECTED = "REJECTED"
    TERMINATED = "TERMINATED"
    PROMOTED = "PROMOTED"


class SeedStatus(StrEnum):
    SUCCESS = "SUCCESS"
    NEGATIVE = "NEGATIVE"
    NULL = "NULL"
    FAILED = "FAILED"
    INVALID = "INVALID"


class SelectionDecision(StrEnum):
    SELECTED = "SELECTED"
    DUPLICATE_SUPPRESSED = "DUPLICATE_SUPPRESSED"
    BUDGET_REJECTED = "BUDGET_REJECTED"
    CONFIRMATORY_RESOURCE_REJECTED = "CONFIRMATORY_RESOURCE_REJECTED"
    INVALID_ACTION_REJECTED = "INVALID_ACTION_REJECTED"
    RESULT_RECORDED = "RESULT_RECORDED"
    PROMOTED = "PROMOTED"
    PROMOTION_REJECTED = "PROMOTION_REJECTED"
    TERMINATED = "TERMINATED"


class DiscoveryEvidenceAuthority(StrEnum):
    """Authority carried by a recorded branch result.

    Diagnostic evidence is useful for branch retention and ranking inspection,
    but it can never authorize promotion.  Only evidence freshly derived from
    immutable registry artifacts by the engine's pinned evaluator resolver can
    carry checked authority.
    """

    NONE = "NONE"
    DIAGNOSTIC_ONLY = "DIAGNOSTIC_ONLY"
    REGISTRY_EVALUATOR_VERIFIED = "REGISTRY_EVALUATOR_VERIFIED"
    REGISTRY_EVALUATOR_INVALIDATED = "REGISTRY_EVALUATOR_INVALIDATED"


class DiscoveryCheck(StrEnum):
    CONTROL = "CONTROL"
    ROBUSTNESS = "ROBUSTNESS"
    FALSIFICATION = "FALSIFICATION"


class ReviewedDiscoveryEvaluator(StrEnum):
    """Closed, code-reviewed semantic evaluators available to discovery."""

    BINARY_ACCURACY_V1 = "BINARY_ACCURACY_V1"


@dataclass(frozen=True)
class DiscoveryBudget:
    """A bounded exploratory budget; confirmatory capacity is always zero."""

    maximum_branches: int = 64
    maximum_actions: int = 256
    maximum_compute_units: int = 1_000
    confirmatory_compute_units: int = 0

    def __post_init__(self) -> None:
        for name in ("maximum_branches", "maximum_actions", "maximum_compute_units"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise DiscoveryError(f"{name} must be a positive integer")
        if self.maximum_branches > MAX_DISCOVERY_BRANCHES:
            raise DiscoveryError("maximum_branches exceeds safety bound")
        if self.maximum_actions > MAX_DISCOVERY_ACTIONS:
            raise DiscoveryError("maximum_actions exceeds safety bound")
        if self.confirmatory_compute_units != 0:
            raise DiscoveryError("discovery has no confirmatory resource budget")


@dataclass(frozen=True)
class DiscoveryProposal:
    """One immutable scientific action proposed against isolated branch state."""

    proposal_id: str
    action: DiscoveryAction
    hypothesis_id: str
    method_identity: str
    code_sha256: str
    configuration_sha256: str
    planned_seeds: tuple[int, ...]
    compute_units: int
    expected_information_value: int
    scientific_importance: int
    uncertainty_reduction: int
    parent_branch_id: str | None = None
    variant_identity: str = "base"
    metric_direction: str = "maximize"
    required_ablations: tuple[str, ...] = ()
    confirmatory_compute_units: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)
    experiment_id: str | None = None
    evaluator_sha256: str | None = None
    evaluator_implementation_sha256: str | None = None
    data_sha256: str | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.proposal_id, "proposal ID")
        validate_identifier(self.hypothesis_id, "hypothesis ID")
        if not isinstance(self.action, DiscoveryAction):
            try:
                object.__setattr__(self, "action", DiscoveryAction(self.action))
            except (TypeError, ValueError) as exc:
                raise DiscoveryError("unknown discovery action") from exc
        if (
            not isinstance(self.method_identity, str)
            or not self.method_identity.strip()
            or len(self.method_identity.encode("utf-8")) > 4_096
        ):
            raise DiscoveryError("method_identity must be bounded non-empty text")
        validate_sha256(self.code_sha256, "code SHA-256")
        validate_sha256(self.configuration_sha256, "configuration SHA-256")
        if not isinstance(self.planned_seeds, tuple):
            object.__setattr__(self, "planned_seeds", tuple(self.planned_seeds))
        if not self.planned_seeds or len(self.planned_seeds) > MAX_DISCOVERY_SEEDS:
            raise DiscoveryError("planned_seeds must be a bounded non-empty tuple")
        if any(isinstance(seed, bool) or not isinstance(seed, int) or seed < 0 for seed in self.planned_seeds):
            raise DiscoveryError("planned seeds must be non-negative integers")
        if len(set(self.planned_seeds)) != len(self.planned_seeds):
            raise DiscoveryError("planned seeds must be unique")
        for name in (
            "compute_units",
            "expected_information_value",
            "scientific_importance",
            "uncertainty_reduction",
            "confirmatory_compute_units",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise DiscoveryError(f"{name} must be a non-negative integer")
        if self.compute_units == 0:
            raise DiscoveryError("compute_units must be positive")
        if self.parent_branch_id is not None:
            validate_identifier(self.parent_branch_id, "parent branch ID")
        if self.experiment_id is not None:
            validate_identifier(self.experiment_id, "experiment ID")
        if self.evaluator_sha256 is not None:
            validate_sha256(self.evaluator_sha256, "evaluator SHA-256")
        if self.evaluator_implementation_sha256 is not None:
            validate_sha256(
                self.evaluator_implementation_sha256,
                "evaluator implementation SHA-256",
            )
        if self.data_sha256 is not None:
            validate_sha256(self.data_sha256, "data SHA-256")
        validate_identifier(self.variant_identity, "variant identity")
        if self.metric_direction not in {"maximize", "minimize"}:
            raise DiscoveryError("metric_direction must be maximize or minimize")
        if not isinstance(self.required_ablations, tuple):
            object.__setattr__(self, "required_ablations", tuple(self.required_ablations))
        if len(self.required_ablations) > MAX_DISCOVERY_ABLATIONS:
            raise DiscoveryError("required ablations exceed safety bound")
        for ablation in self.required_ablations:
            validate_identifier(ablation, "ablation ID")
        if len(set(self.required_ablations)) != len(self.required_ablations):
            raise DiscoveryError("required ablations must be unique")
        if not isinstance(self.metadata, Mapping):
            raise DiscoveryError("proposal metadata must be a mapping")
        object.__setattr__(self, "metadata", freeze_json(dict(self.metadata)))

    def identity_payload(self) -> dict[str, Any]:
        """Return the scientific identity used for duplicate suppression."""

        return {
            "action": self.action.value,
            "hypothesis_id": self.hypothesis_id,
            "method_identity": self.method_identity,
            "code_sha256": self.code_sha256,
            "configuration_sha256": self.configuration_sha256,
            "data_sha256": self.data_sha256,
            "experiment_id": self.experiment_id,
            "evaluator_sha256": self.evaluator_sha256,
            "evaluator_implementation_sha256": (
                self.evaluator_implementation_sha256
            ),
            "planned_seeds": list(self.planned_seeds),
            "variant_identity": self.variant_identity,
            "metric_direction": self.metric_direction,
            "required_ablations": list(self.required_ablations),
            "metadata": thaw_json(self.metadata),
        }

    def scientific_fingerprint(
        self, parent_snapshot_sha256: str | None = None
    ) -> str:
        """Hash the complete scientific identity frozen before execution."""

        if parent_snapshot_sha256 is not None:
            validate_sha256(parent_snapshot_sha256, "parent snapshot SHA-256")
        payload = self.identity_payload()
        payload["parent_snapshot_sha256"] = parent_snapshot_sha256
        return _sha256_json(payload)


@dataclass(frozen=True)
class SeedObservation:
    seed: int
    status: SeedStatus
    metric: float | None = None
    output_sha256: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.seed, bool) or not isinstance(self.seed, int) or self.seed < 0:
            raise DiscoveryError("seed must be a non-negative integer")
        if not isinstance(self.status, SeedStatus):
            try:
                object.__setattr__(self, "status", SeedStatus(self.status))
            except (TypeError, ValueError) as exc:
                raise DiscoveryError("unknown seed status") from exc
        if self.metric is not None:
            if isinstance(self.metric, bool) or not isinstance(self.metric, (int, float)):
                raise DiscoveryError("seed metric must be numeric")
            if not math.isfinite(float(self.metric)):
                raise DiscoveryError("seed metric must be finite")
            object.__setattr__(self, "metric", float(self.metric))
        if self.output_sha256 is not None:
            validate_sha256(self.output_sha256, "seed output SHA-256")
        if self.status in {SeedStatus.SUCCESS, SeedStatus.NEGATIVE, SeedStatus.NULL}:
            if self.metric is None or self.output_sha256 is None:
                raise DiscoveryError("evidentiary seed results require metric and output hash")
        if self.status in {SeedStatus.FAILED, SeedStatus.INVALID}:
            if not isinstance(self.reason, str) or not self.reason.strip():
                raise DiscoveryError("failed or invalid seed results require a reason")
        if self.reason is not None and len(self.reason.encode("utf-8")) > 4_096:
            raise DiscoveryError("seed reason exceeds size bound")


@dataclass(frozen=True)
class AblationEvidence:
    ablation_id: str
    artifact_sha256: str | None
    verified: bool
    source_experiment_id: str | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.ablation_id, "ablation ID")
        if self.artifact_sha256 is not None:
            validate_sha256(self.artifact_sha256, "ablation artifact SHA-256")
        if not isinstance(self.verified, bool):
            raise DiscoveryError("ablation verified flag must be boolean")
        if self.source_experiment_id is not None:
            validate_identifier(self.source_experiment_id, "source experiment ID")
        if self.verified and (self.artifact_sha256 is None or self.source_experiment_id is None):
            raise DiscoveryError("verified ablation evidence requires artifact and experiment identities")


@dataclass(frozen=True)
class BranchEvidence:
    seed_observations: tuple[SeedObservation, ...]
    ablations: tuple[AblationEvidence, ...] = ()
    control_passed: bool = True
    # ``None`` means the reviewed evaluator explicitly declares robustness
    # inapplicable.  It is not silently converted into a passing gate.
    robustness_passed: bool | None = True
    falsification_survived: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.seed_observations, tuple):
            object.__setattr__(self, "seed_observations", tuple(self.seed_observations))
        if not isinstance(self.ablations, tuple):
            object.__setattr__(self, "ablations", tuple(self.ablations))
        if len(self.seed_observations) > MAX_DISCOVERY_SEEDS:
            raise DiscoveryError("seed observations exceed safety bound")
        if len(self.ablations) > MAX_DISCOVERY_ABLATIONS:
            raise DiscoveryError("ablation evidence exceeds safety bound")
        if not all(isinstance(item, SeedObservation) for item in self.seed_observations):
            raise DiscoveryError("seed observations must be typed")
        if not all(isinstance(item, AblationEvidence) for item in self.ablations):
            raise DiscoveryError("ablation evidence must be typed")
        for name in ("control_passed", "falsification_survived"):
            if not isinstance(getattr(self, name), bool):
                raise DiscoveryError(f"{name} must be boolean")
        if self.robustness_passed is not None and not isinstance(
            self.robustness_passed, bool
        ):
            raise DiscoveryError("robustness_passed must be boolean or None")


@dataclass(frozen=True)
class RegisteredBranchEvidence:
    """Registry identities from which checked discovery evidence is derived.

    This type intentionally contains no metrics, seed statuses, ablation
    verification flags, or control booleans.  Those semantic values must be
    recomputed by the pinned evaluator from the referenced immutable bytes.
    """

    source_experiment_id: str
    frozen_run_spec_sha256: str
    output_manifest_sha256: str
    execution_plan_binding_sha256: str
    ledger_event_id: str
    seed_output_sha256s: Mapping[int, str]
    ablation_artifact_sha256s: Mapping[str, str]
    control_artifact_sha256: str
    robustness_artifact_sha256: str
    falsification_artifact_sha256: str

    def __post_init__(self) -> None:
        validate_identifier(self.source_experiment_id, "source experiment ID")
        validate_identifier(self.ledger_event_id, "ledger event ID")
        for name in (
            "frozen_run_spec_sha256",
            "output_manifest_sha256",
            "execution_plan_binding_sha256",
        ):
            validate_sha256(getattr(self, name), name.replace("_", " "))
        if not isinstance(self.seed_output_sha256s, Mapping):
            raise DiscoveryError("seed output artifacts must be a mapping")
        if not isinstance(self.ablation_artifact_sha256s, Mapping):
            raise DiscoveryError("ablation artifacts must be a mapping")
        if len(self.seed_output_sha256s) > MAX_DISCOVERY_SEEDS:
            raise DiscoveryError("seed output artifacts exceed safety bound")
        if len(self.ablation_artifact_sha256s) > MAX_DISCOVERY_ABLATIONS:
            raise DiscoveryError("ablation artifacts exceed safety bound")
        seeds: dict[int, str] = {}
        for seed, digest in self.seed_output_sha256s.items():
            if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
                raise DiscoveryError("seed output artifact keys must be non-negative integers")
            validate_sha256(digest, "seed output artifact SHA-256")
            seeds[seed] = digest
        ablations: dict[str, str] = {}
        for ablation_id, digest in self.ablation_artifact_sha256s.items():
            validate_identifier(ablation_id, "ablation ID")
            validate_sha256(digest, "ablation artifact SHA-256")
            ablations[ablation_id] = digest
        for name in (
            "control_artifact_sha256",
            "robustness_artifact_sha256",
            "falsification_artifact_sha256",
        ):
            validate_sha256(getattr(self, name), name.replace("_", " "))
        all_hashes = (
            self.frozen_run_spec_sha256,
            self.output_manifest_sha256,
            self.execution_plan_binding_sha256,
            *seeds.values(),
            *ablations.values(),
            self.control_artifact_sha256,
            self.robustness_artifact_sha256,
            self.falsification_artifact_sha256,
        )
        if len(set(all_hashes)) != len(all_hashes):
            raise DiscoveryError("checked evidence artifacts must have distinct identities")
        object.__setattr__(self, "seed_output_sha256s", MappingProxyType(seeds))
        object.__setattr__(
            self,
            "ablation_artifact_sha256s",
            MappingProxyType(ablations),
        )

    def check_artifact_sha256(self, check: DiscoveryCheck) -> str:
        if check is DiscoveryCheck.CONTROL:
            return self.control_artifact_sha256
        if check is DiscoveryCheck.ROBUSTNESS:
            return self.robustness_artifact_sha256
        if check is DiscoveryCheck.FALSIFICATION:
            return self.falsification_artifact_sha256
        raise DiscoveryError("unknown discovery check")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_experiment_id": self.source_experiment_id,
            "frozen_run_spec_sha256": self.frozen_run_spec_sha256,
            "output_manifest_sha256": self.output_manifest_sha256,
            "execution_plan_binding_sha256": self.execution_plan_binding_sha256,
            "ledger_event_id": self.ledger_event_id,
            "seed_output_sha256s": {
                str(seed): digest
                for seed, digest in sorted(self.seed_output_sha256s.items())
            },
            "ablation_artifact_sha256s": {
                ablation_id: digest
                for ablation_id, digest in sorted(
                    self.ablation_artifact_sha256s.items()
                )
            },
            "control_artifact_sha256": self.control_artifact_sha256,
            "robustness_artifact_sha256": self.robustness_artifact_sha256,
            "falsification_artifact_sha256": self.falsification_artifact_sha256,
        }


@dataclass(frozen=True)
class _ResolvedCheckedEvidence:
    evidence: BranchEvidence
    receipt_payload: Mapping[str, Any]
    receipt_parents: tuple[str, ...]


_CHECK_LOGICAL_TYPES = {
    DiscoveryCheck.CONTROL: "discovery_check.control",
    DiscoveryCheck.ROBUSTNESS: "discovery_check.robustness",
    DiscoveryCheck.FALSIFICATION: "discovery_check.falsification",
}
_CHECK_CREATOR_ROLES = {
    DiscoveryCheck.CONTROL: Role.SCIENTIFIC_REVIEWER,
    DiscoveryCheck.ROBUSTNESS: Role.REPRODUCTION_VERIFIER,
    DiscoveryCheck.FALSIFICATION: Role.ADVERSARIAL_REVIEWER,
}

_REGISTRY_SECURITY_METHODS = (
    "verify",
    "verify_all",
    "get_metadata",
    "get_bytes",
    "list_records",
    "put_json",
    "put_bytes",
)
_LEDGER_SECURITY_METHODS = (
    "events",
    "assert_valid",
    "validate",
)


def _branch_evidence_payload(evidence: BranchEvidence) -> dict[str, Any]:
    return {
        "seeds": [
            {
                "seed": item.seed,
                "status": item.status.value,
                "metric": item.metric,
                "output_sha256": item.output_sha256,
                "reason": item.reason,
            }
            for item in evidence.seed_observations
        ],
        "ablations": [
            {
                "ablation_id": item.ablation_id,
                "artifact_sha256": item.artifact_sha256,
                "verified": item.verified,
                "source_experiment_id": item.source_experiment_id,
            }
            for item in evidence.ablations
        ],
        "control_passed": evidence.control_passed,
        "robustness_passed": evidence.robustness_passed,
        "falsification_survived": evidence.falsification_survived,
    }


_RESOLVER_SECURITY_METHODS = (
    "_verify_resolver_is_pinned",
    "_canonical_mapping",
    "_validate_evaluator_contract",
    "_validate_implementation_contract",
    "_require_artifact",
    "_artifact_ancestors",
    "_require_ancestry",
    "_binary_vector",
    "_fraction",
    "_expected_binary_accuracy_vectors",
    "_resolve_ledger_event",
    "_resolve_run_custody",
    "_resolve_seed_payload",
    "_resolve_ablation_payload",
    "_resolve_check",
    "_resolve",
    "_reject_distinct_evidence_reuse",
    "evaluate_and_register",
    "register_rejection",
    "revalidate_rejection",
    "_checked_classification",
    "_validate_checked_branch_state",
    "_promotion_contract",
    "register_promotion",
    "register_promotion_rejection",
    "revalidate",
    "revalidate_promotion",
    "revalidate_promotion_rejection",
)


class RegistryDiscoveryEvidenceResolver:
    """Resolve checked results through closed, reviewed evaluator code.

    The resolver does not accept callbacks.  The evaluator artifact selects a
    reviewed in-module implementation, while the registry supplies a complete
    frozen-run/spec/manifest/execution-binding custody chain.  Consequently a
    caller cannot gain promotion authority by registering JSON booleans or by
    presenting a deterministic callback that merely claims an evaluator hash.
    """

    __slots__ = (
        "_registry",
        "_admitted_registry",
        "_ledger",
        "_admitted_ledger",
        "_ledger_dispatch",
        "_registry_security_dispatch",
        "_ledger_security_dispatch",
        "_admitted_root",
        "_admitted_registry_base_path",
        "_admitted_ledger_relative_path",
        "_admitted_registry_namespace",
        "_admitted_ledger_namespace",
        "_evaluator_sha256",
        "_admitted_evaluator_sha256",
        "_reviewed_evaluator",
        "_admitted_reviewed_evaluator",
        "_security_dispatch",
    )

    def __init__(
        self,
        registry: ArtifactRegistry,
        evaluator_sha256: str,
        *,
        ledger: EventLedger,
        reviewed_evaluator: ReviewedDiscoveryEvaluator = (
            ReviewedDiscoveryEvaluator.BINARY_ACCURACY_V1
        ),
    ) -> None:
        if type(registry) is not ArtifactRegistry:
            raise DiscoveryError("checked discovery requires an exact ArtifactRegistry")
        if type(ledger) is not EventLedger:
            raise DiscoveryError("checked discovery requires an exact EventLedger")
        if registry.policy.root != ledger.policy.root:
            raise DiscoveryError("checked discovery registry and ledger roots differ")
        if (
            registry.base_path.name != "registry"
            or ledger.relative_path.name != "events.jsonl"
            or registry.base_path.parent != ledger.relative_path.parent
        ):
            raise DiscoveryError(
                "checked discovery requires the canonical paired run registry and ledger"
            )
        validate_sha256(evaluator_sha256, "discovery evaluator SHA-256")
        if not isinstance(reviewed_evaluator, ReviewedDiscoveryEvaluator):
            try:
                reviewed_evaluator = ReviewedDiscoveryEvaluator(reviewed_evaluator)
            except (TypeError, ValueError) as exc:
                raise DiscoveryError("unknown reviewed discovery evaluator") from exc
        self._registry = registry
        self._admitted_registry = registry
        self._ledger = ledger
        self._admitted_ledger = ledger
        self._ledger_dispatch = EventLedger.events
        self._registry_security_dispatch = tuple(
            getattr(ArtifactRegistry, name)
            for name in _REGISTRY_SECURITY_METHODS
        )
        self._ledger_security_dispatch = tuple(
            getattr(EventLedger, name) for name in _LEDGER_SECURITY_METHODS
        )
        self._admitted_root = registry.policy.root
        self._admitted_registry_base_path = registry.base_path
        self._admitted_ledger_relative_path = ledger.relative_path
        self._admitted_registry_namespace = (
            registry._root_identity,
            registry._base_identity,
        )
        self._admitted_ledger_namespace = (
            ledger._root_identity,
            ledger._parent_identity,
        )
        self._evaluator_sha256 = evaluator_sha256
        self._admitted_evaluator_sha256 = evaluator_sha256
        self._reviewed_evaluator = reviewed_evaluator
        self._admitted_reviewed_evaluator = reviewed_evaluator
        self._security_dispatch = tuple(
            getattr(type(self), name) for name in _RESOLVER_SECURITY_METHODS
        )
        _, evaluator_bytes = self._require_artifact(
            evaluator_sha256,
            logical_type="metric_evaluator",
            creator_role=Role.PROTOCOL_DESIGNER,
        )
        self._validate_evaluator_contract(evaluator_bytes)

    @property
    def evaluator_sha256(self) -> str:
        return self._evaluator_sha256

    @property
    def evaluator_implementation_id(self) -> str:
        return self._reviewed_evaluator.value

    def _verify_resolver_is_pinned(self) -> None:
        if (
            self._registry is not self._admitted_registry
            or self._ledger is not self._admitted_ledger
            or type(self._registry) is not ArtifactRegistry
            or type(self._ledger) is not EventLedger
            or self._registry.policy.root != self._admitted_root
            or self._ledger.policy.root != self._admitted_root
            or self._registry.base_path
            != self._admitted_registry_base_path
            or self._ledger.relative_path
            != self._admitted_ledger_relative_path
            or (
                self._registry._root_identity,
                self._registry._base_identity,
            )
            != self._admitted_registry_namespace
            or (
                self._ledger._root_identity,
                self._ledger._parent_identity,
            )
            != self._admitted_ledger_namespace
            or self._registry.policy.root != self._ledger.policy.root
            or self._registry.base_path.name != "registry"
            or self._ledger.relative_path.name != "events.jsonl"
            or self._registry.base_path.parent
            != self._ledger.relative_path.parent
            or EventLedger.events is not self._ledger_dispatch
            or tuple(
                getattr(ArtifactRegistry, name)
                for name in _REGISTRY_SECURITY_METHODS
            )
            != self._registry_security_dispatch
            or tuple(
                getattr(EventLedger, name)
                for name in _LEDGER_SECURITY_METHODS
            )
            != self._ledger_security_dispatch
            or self._evaluator_sha256 != self._admitted_evaluator_sha256
            or self._reviewed_evaluator is not self._admitted_reviewed_evaluator
            or tuple(
                getattr(type(self), name) for name in _RESOLVER_SECURITY_METHODS
            )
            != self._security_dispatch
        ):
            raise DiscoveryIntegrityError("discovery resolver binding or dispatch changed")

    @staticmethod
    def _canonical_mapping(content: bytes, label: str) -> Mapping[str, Any]:
        try:
            value = safe_json_loads(content)
        except Exception as exc:
            raise DiscoveryIntegrityError(f"{label} is not valid JSON") from exc
        if (
            not isinstance(value, Mapping)
            or content != canonical_json_bytes(value) + b"\n"
        ):
            raise DiscoveryIntegrityError(f"{label} is not canonical JSON")
        return value

    def _validate_evaluator_contract(self, content: bytes) -> None:
        value = self._canonical_mapping(content, "metric evaluator")
        if self._reviewed_evaluator is ReviewedDiscoveryEvaluator.BINARY_ACCURACY_V1:
            if (
                value.get("version") != "accuracy-evaluator-v1"
                or value.get("metric_id") != "subject-accuracy"
                or value.get("unit") != "fraction"
                or value.get("aggregation")
                != "arithmetic mean over all declared seeds"
                or value.get("definition")
                != "correct development subjects divided by all development subjects"
            ):
                raise DiscoveryIntegrityError(
                    "metric evaluator artifact is not compatible with reviewed code"
                )
            return
        raise DiscoveryIntegrityError("reviewed discovery evaluator is unavailable")

    def _validate_implementation_contract(self, content: bytes) -> None:
        value = self._canonical_mapping(content, "discovery implementation snapshot")
        files = value.get("files")
        if (
            value.get("schema_version")
            != "SCIENTIST_ONE_VNEXT_SOURCE_SNAPSHOT_V1"
            or not isinstance(files, list)
        ):
            raise DiscoveryIntegrityError(
                "discovery implementation snapshot is malformed"
            )
        matches = tuple(
            item
            for item in files
            if isinstance(item, Mapping)
            and item.get("path") == "src/scientist_one/discovery.py"
        )
        if (
            len(matches) != 1
            or set(matches[0]) != {"path", "sha256"}
            or matches[0].get("sha256") != _DISCOVERY_IMPLEMENTATION_SHA256
        ):
            raise DiscoveryIntegrityError(
                "reviewed discovery implementation source is not exactly pinned"
            )

    def _require_artifact(
        self,
        digest: str,
        *,
        logical_type: str,
        creator_role: Role,
    ) -> tuple[ArtifactRecord, bytes]:
        try:
            if self._registry.verify(digest, raise_on_error=True) is not True:
                raise DiscoveryIntegrityError("registry did not verify discovery evidence")
            record = self._registry.get_metadata(digest)
            content = self._registry.get_bytes(digest)
        except Exception as exc:
            raise DiscoveryIntegrityError("discovery artifact is absent or corrupt") from exc
        if (
            record.sha256 != digest
            or hashlib.sha256(content).hexdigest() != digest
            or record.logical_type != logical_type
            or record.creator_role is not creator_role
            or record.validation_result != "PASS"
            or record.frozen is not True
        ):
            raise DiscoveryIntegrityError("discovery artifact registry contract is invalid")
        return record, content

    def _artifact_ancestors(self, digest: str) -> frozenset[str]:
        ancestors: set[str] = set()
        pending = [digest]
        while pending:
            current = pending.pop()
            if current in ancestors:
                continue
            ancestors.add(current)
            try:
                record = self._registry.get_metadata(current)
            except Exception as exc:
                raise DiscoveryIntegrityError("discovery provenance graph is corrupt") from exc
            pending.extend(record.parent_artifacts)
            if len(ancestors) > 250_000:
                raise DiscoveryIntegrityError("discovery provenance graph exceeds safety bound")
        ancestors.discard(digest)
        return frozenset(ancestors)

    def _require_ancestry(self, digest: str, required: Iterable[str]) -> None:
        missing = set(required) - self._artifact_ancestors(digest)
        if missing:
            raise DiscoveryIntegrityError("discovery artifact lacks required provenance ancestry")

    @staticmethod
    def _binary_vector(value: Any, label: str) -> tuple[float, ...]:
        if (
            not isinstance(value, list)
            or not value
            or any(
                isinstance(item, bool)
                or not isinstance(item, int)
                or item not in {0, 1}
                for item in value
            )
        ):
            raise DiscoveryIntegrityError(f"{label} must be a non-empty binary vector")
        return tuple(float(item) for item in value)

    @staticmethod
    def _fraction(value: Any, label: str) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or not 0.0 <= float(value) <= 1.0
        ):
            raise DiscoveryIntegrityError(f"{label} must be a finite fraction")
        return float(value)

    def _expected_binary_accuracy_vectors(
        self,
        data_bytes: bytes,
        configuration_bytes: bytes,
    ) -> tuple[tuple[float, ...], tuple[float, ...], str]:
        try:
            data = safe_json_loads(data_bytes)
        except Exception as exc:
            raise DiscoveryIntegrityError("discovery dataset is not valid JSON") from exc
        if not isinstance(data, Mapping):
            raise DiscoveryIntegrityError("discovery dataset must be a JSON object")
        configuration = self._canonical_mapping(
            configuration_bytes, "experiment configuration"
        )
        rows = data.get("rows")
        split = configuration.get("evaluation_split")
        threshold = configuration.get("candidate_threshold")
        if (
            not isinstance(rows, list)
            or not isinstance(split, str)
            or not split
            or isinstance(threshold, bool)
            or not isinstance(threshold, (int, float))
            or not math.isfinite(float(threshold))
        ):
            raise DiscoveryIntegrityError(
                "dataset or configuration cannot drive the reviewed evaluator"
            )
        if (
            split != "development"
            or configuration.get("required_ablations") != ["remove-signal"]
            or configuration.get("ablation_interventions")
            != {
                "remove-signal": (
                    "replace candidate with frozen constant-zero baseline"
                )
            }
        ):
            raise DiscoveryIntegrityError(
                "reviewed exploratory evaluator requires the development split and frozen removal control"
            )
        candidate: list[float] = []
        baseline: list[float] = []
        for row in rows:
            if not isinstance(row, Mapping) or row.get("split") != split:
                continue
            label = row.get("label")
            signal = row.get("signal")
            if (
                isinstance(label, bool)
                or label not in {0, 1}
                or isinstance(signal, bool)
                or not isinstance(signal, (int, float))
                or not math.isfinite(float(signal))
            ):
                raise DiscoveryIntegrityError("reviewed evaluator input row is invalid")
            baseline.append(float(int(label == 0)))
            candidate.append(
                float(int((float(signal) >= float(threshold)) == bool(label)))
            )
        if not candidate:
            raise DiscoveryIntegrityError("reviewed evaluator split is empty")
        method_identity = f"pinned-threshold-{format(float(threshold), '.12g')}"
        return tuple(candidate), tuple(baseline), method_identity

    def _resolve_ledger_event(
        self,
        registered: RegisteredBranchEvidence,
    ) -> LedgerEvent:
        self._verify_resolver_is_pinned()
        try:
            events = tuple(self._ledger.events())
            matches = tuple(
                event
                for event in events
                if event.event_id == registered.ledger_event_id
            )
        except Exception as exc:
            raise DiscoveryIntegrityError(
                "discovery execution ledger cannot be verified"
            ) from exc
        if len(matches) != 1:
            raise DiscoveryIntegrityError(
                "discovery execution ledger event is absent or ambiguous"
            )
        if any(
            event.event_type == "CORRECTION"
            and event.supersedes_event_id == registered.ledger_event_id
            for event in events
        ):
            raise DiscoveryIntegrityError(
                "discovery execution ledger event has been superseded"
            )
        return matches[0]

    def _resolve_run_custody(
        self,
        branch: "BranchRecord",
        registered: RegisteredBranchEvidence,
        configuration: Mapping[str, Any],
    ) -> tuple[
        ArtifactRecord,
        Mapping[str, Any],
        str,
        ArtifactRecord,
        OutputManifest,
        ArtifactRecord,
        ArtifactRecord,
        ArtifactRecord,
        LedgerEvent,
    ]:
        proposal = branch.proposal
        spec_record, spec_bytes = self._require_artifact(
            registered.frozen_run_spec_sha256,
            logical_type="frozen_run_spec",
            creator_role=Role.EXPERIMENT_RUNNER,
        )
        spec = self._canonical_mapping(spec_bytes, "frozen run spec")
        if spec.get("schema_version") != "SCIENTIST_ONE_FROZEN_RUN_SPEC_V1":
            raise DiscoveryIntegrityError("unsupported frozen run spec")
        semantic_spec_sha256 = hashlib.sha256(canonical_json_bytes(spec)).hexdigest()
        metadata = spec.get("metadata")
        if (
            spec.get("experiment_id") != proposal.experiment_id
            or spec.get("hypothesis_id") != proposal.hypothesis_id
            or spec.get("phase") != "EXPLORATORY"
            or spec.get("code_sha256") != proposal.code_sha256
            or spec.get("data_sha256") != proposal.data_sha256
            or spec.get("configuration_sha256") != proposal.configuration_sha256
            or spec.get("evaluator_sha256") != proposal.evaluator_sha256
            or spec.get("seeds") != list(proposal.planned_seeds)
            or spec.get("required_ablations")
            != list(proposal.required_ablations)
            or spec.get("network_allowed") is not False
            or spec.get("shell_allowed") is not False
            or spec.get("evidence_class") != "NON_EVIDENTIARY"
            or spec.get("argv")
            != [
                "/usr/bin/python3",
                "-I",
                "-S",
                "-B",
                "scripts/vnext_fixture_experiment.py",
            ]
            or spec.get("working_directory") != "."
            or not isinstance(metadata, Mapping)
            or metadata.get("discovery_proposal_fingerprint")
            != branch.scientific_fingerprint
            or metadata.get("discovery_evaluator_implementation_sha256")
            != proposal.evaluator_implementation_sha256
            or metadata.get("scientific_evidence_eligible") is not False
            or metadata.get("evaluation_split")
            != configuration.get("evaluation_split")
            or metadata.get("evaluation_split") != "development"
            or metadata.get("candidate_threshold")
            != configuration.get("candidate_threshold")
            or metadata.get("dataset_path")
            != configuration.get("dataset_path")
        ):
            raise DiscoveryIntegrityError("frozen run spec differs from proposal identity")

        manifest_record, manifest_bytes = self._require_artifact(
            registered.output_manifest_sha256,
            logical_type="experiment_output_manifest",
            creator_role=Role.EXPERIMENT_RUNNER,
        )
        manifest_value = self._canonical_mapping(
            manifest_bytes, "experiment output manifest"
        )
        try:
            manifest = OutputManifest.from_mapping(manifest_value)
        except Exception as exc:
            raise DiscoveryIntegrityError("experiment output manifest is malformed") from exc
        if manifest_bytes != canonical_json_bytes(manifest.to_dict()) + b"\n":
            raise DiscoveryIntegrityError("experiment output manifest is not canonical")
        if (
            manifest.run_id != spec.get("run_id")
            or manifest.spec_sha256 != semantic_spec_sha256
            or manifest.code_sha256 != proposal.code_sha256
            or manifest.data_sha256 != proposal.data_sha256
            or manifest.configuration_sha256 != proposal.configuration_sha256
            or manifest.evaluator_sha256 != proposal.evaluator_sha256
            or manifest.planned_seeds != proposal.planned_seeds
            or spec_record.sha256 not in manifest_record.parent_artifacts
        ):
            raise DiscoveryIntegrityError("output manifest differs from frozen run")
        seed_result_ids = tuple(item.seed for item in manifest.seed_results)
        output_hashes = tuple(item.sha256 for item in manifest.artifacts)
        ablation_ids = tuple(item.ablation_id for item in manifest.ablations)
        expected_output_hashes = {
            *registered.seed_output_sha256s.values(),
            *registered.ablation_artifact_sha256s.values(),
        }
        if (
            len(set(seed_result_ids)) != len(seed_result_ids)
            or set(seed_result_ids) != set(proposal.planned_seeds)
            or len(set(output_hashes)) != len(output_hashes)
            or set(output_hashes) != expected_output_hashes
            or len(set(ablation_ids)) != len(ablation_ids)
            or set(ablation_ids) != set(proposal.required_ablations)
        ):
            raise DiscoveryIntegrityError("output manifest result inventory is not exact")

        binding_record, binding_bytes = self._require_artifact(
            registered.execution_plan_binding_sha256,
            logical_type="adaptive_execution_plan_binding",
            creator_role=Role.EXPERIMENT_RUNNER,
        )
        binding = self._canonical_mapping(
            binding_bytes, "execution plan custody binding"
        )
        expected_binding_fields = {
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
        if (
            set(binding) != expected_binding_fields
            or
            binding.get("agreement") is not True
            or binding.get("backend_id") != "local-mac"
            or binding.get("submission_backend_id") != "local-mac"
            or binding.get("collected_backend_id") != "local-mac"
            or binding.get("run_id") != spec.get("run_id")
            or binding.get("spec_artifact_sha256") != spec_record.sha256
            or binding.get("spec_sha256") != semantic_spec_sha256
            or binding.get("submission_spec_sha256") != semantic_spec_sha256
            or binding.get("collected_spec_sha256") != semantic_spec_sha256
            or binding.get("submission_execution_plan_sha256")
            != binding.get("execution_plan_sha256")
            or binding.get("submission_execution_input_binding_sha256")
            != binding.get("execution_input_binding_artifact_sha256")
            or binding.get("collected_execution_plan_sha256")
            != binding.get("execution_plan_sha256")
            or binding.get("collected_execution_input_binding_sha256")
            != binding.get("execution_input_binding_artifact_sha256")
            or binding.get("execution_input_binding_sha256")
            != binding.get("execution_input_binding_artifact_sha256")
            or binding.get("collected_manifest_sha256") != manifest_record.sha256
            or binding.get("collected_returned_artifact_sha256s")
            != list(output_hashes)
            or binding.get("submission_state") != "SUCCEEDED"
            or binding.get("submission_validation_status") != "VALIDATED_LOCAL"
            or binding.get("collected_validation_status") != "VALIDATED_LOCAL"
            or binding.get("submission_network_used") is not False
            or binding.get("collected_network_used") is not False
            or binding.get("submission_network_isolation_attested") is not False
            or binding.get("collected_network_isolation_attested") is not False
            or binding.get("submission_scientific_evidence") is not False
            or binding.get("collected_scientific_evidence") is not False
        ):
            raise DiscoveryIntegrityError("execution plan custody is not exact")
        execution_input_binding_sha256 = binding.get(
            "execution_input_binding_artifact_sha256"
        )
        if not isinstance(execution_input_binding_sha256, str):
            raise DiscoveryIntegrityError("execution input binding identity is absent")
        input_binding_record, input_binding_bytes = self._require_artifact(
            execution_input_binding_sha256,
            logical_type="execution_input_binding",
            creator_role=Role.EXPERIMENT_RUNNER,
        )
        input_binding = self._canonical_mapping(
            input_binding_bytes, "execution input binding"
        )
        if (
            input_binding_record.origin
            != "exact local execution input-byte binding"
            or input_binding_record.creation_command
            != (
                "scientist-one",
                "research-os-fixture",
                "capture-execution-input-binding",
            )
            or input_binding_record.parent_artifacts != (spec_record.sha256,)
            or input_binding_record.schema_version != "1.0"
            or input_binding_record.mime_type != "application/json"
            or set(input_binding)
            != {
                "schema_version",
                "spec_sha256",
                "inputs",
                "consumption",
                "scientific_evidence",
            }
            or input_binding.get("schema_version")
            != "SCIENTIST_ONE_LOCAL_MAC_EXECUTION_INPUT_BINDING_V1"
            or input_binding.get("spec_sha256") != semantic_spec_sha256
            or input_binding.get("consumption") != "PARENT_HELD_READ_DESCRIPTORS"
            or input_binding.get("scientific_evidence") is not False
            or not isinstance(input_binding.get("inputs"), list)
        ):
            raise DiscoveryIntegrityError("execution input binding custody is not exact")
        expected_inputs = (
            ("code", proposal.code_sha256, ".py"),
            ("data", proposal.data_sha256, ".bin"),
            ("configuration", proposal.configuration_sha256, ".bin"),
            ("evaluator", proposal.evaluator_sha256, ".bin"),
        )
        if len(input_binding["inputs"]) != len(expected_inputs):
            raise DiscoveryIntegrityError("execution input binding count is not exact")
        for observed, (kind, digest, suffix) in zip(
            input_binding["inputs"], expected_inputs
        ):
            try:
                frozen_bytes = self._registry.get_bytes(digest)
            except Exception as exc:
                raise DiscoveryIntegrityError(
                    "execution input binding cannot reopen its frozen input"
                ) from exc
            if (
                not isinstance(observed, Mapping)
                or set(observed) != {"kind", "sha256", "size", "staged_name"}
                or observed.get("kind") != kind
                or observed.get("sha256") != digest
                or observed.get("size") != len(frozen_bytes)
                or observed.get("staged_name") != f"frozen-input-{kind}{suffix}"
            ):
                raise DiscoveryIntegrityError(
                    "execution input binding differs from the frozen run spec"
                )
        try:
            validate_identifier(binding["job_id"], "backend job ID")
            validate_identifier(
                binding["submission_idempotency_key"], "submission idempotency key"
            )
        except ValidationError as exc:
            raise DiscoveryIntegrityError("backend custody identity is invalid") from exc
        plan_record, plan_bytes = self._require_artifact(
            binding["execution_plan_artifact_sha256"],
            logical_type="adaptive_execution_plan",
            creator_role=Role.EXPERIMENT_RUNNER,
        )
        try:
            plan = AdaptiveExecutionPlan.from_mapping(
                self._canonical_mapping(plan_bytes, "adaptive execution plan")
            )
        except Exception as exc:
            raise DiscoveryIntegrityError("adaptive execution plan is malformed") from exc
        compute_profile = spec.get("compute_profile")
        if (
            not isinstance(compute_profile, Mapping)
            or plan_bytes != canonical_json_bytes(plan.to_dict()) + b"\n"
            or plan.sha256 != binding.get("execution_plan_sha256")
            or plan.profile_sha256 != _sha256_json(compute_profile)
            or binding_record.parent_artifacts
            != (
                plan_record.sha256,
                input_binding_record.sha256,
                spec_record.sha256,
            )
        ):
            raise DiscoveryIntegrityError("adaptive execution plan binding is invalid")

        ledger_event = self._resolve_ledger_event(registered)
        required_event_artifacts = {
            spec_record.sha256,
            plan_record.sha256,
            input_binding_record.sha256,
            binding_record.sha256,
            manifest_record.sha256,
            *output_hashes,
        }
        event_metadata = ledger_event.metadata
        expected_evaluator_output = {
            "evidence_class": "SYSTEM_FIXTURE",
            "execution_plan_artifact_sha256": plan_record.sha256,
            "execution_plan_sha256": plan.sha256,
            "manifest_sha256": manifest_record.sha256,
            "os_enforced_sandbox": False,
            "scientific_evidence": False,
            "validation_status": "VALIDATED_LOCAL",
        }
        if (
            ledger_event.actor_role is not Role.EXPERIMENT_RUNNER
            or ledger_event.event_type != "CHECKPOINT"
            or ledger_event.configuration_hash != proposal.configuration_sha256
            or ledger_event.random_seeds != proposal.planned_seeds
            or ledger_event.code_version
            != f"sha256:{proposal.evaluator_implementation_sha256}"
            or not required_event_artifacts.issubset(ledger_event.artifact_hashes)
            or len(ledger_event.evaluator_outputs) != 1
            or dict(ledger_event.evaluator_outputs[0]) != expected_evaluator_output
            or event_metadata.get("backend_id") != "local-mac"
            or event_metadata.get("experiment_run_id") != spec.get("run_id")
            or event_metadata.get("execution_plan_binding_sha256")
            != binding_record.sha256
            or event_metadata.get("promotion")
            != "EXPERIMENT_OUTPUTS_REGISTERED"
            or event_metadata.get("scientific_evidence_eligible") is not False
        ):
            raise DiscoveryIntegrityError(
                "ledger does not bind exact submission, execution, and collection custody"
            )
        return (
            spec_record,
            spec,
            semantic_spec_sha256,
            manifest_record,
            manifest,
            binding_record,
            input_binding_record,
            plan_record,
            ledger_event,
        )

    def _resolve_seed_payload(
        self,
        *,
        seed: int,
        digest: str,
        proposal: DiscoveryProposal,
        spec_record: ArtifactRecord,
        spec: Mapping[str, Any],
        manifest_record: ArtifactRecord,
        manifest: OutputManifest,
        expected_candidate: tuple[float, ...],
        expected_baseline: tuple[float, ...],
    ) -> tuple[SeedObservation, Mapping[str, Any]]:
        record, content = self._require_artifact(
            digest,
            logical_type="experiment_output.seed_result",
            creator_role=Role.EXPERIMENT_RUNNER,
        )
        if not {spec_record.sha256, manifest_record.sha256}.issubset(
            record.parent_artifacts
        ):
            raise DiscoveryIntegrityError("seed output lacks direct run custody")
        descriptor_by_hash = {item.sha256: item for item in manifest.artifacts}
        descriptor = descriptor_by_hash.get(digest)
        result_by_seed = {item.seed: item for item in manifest.seed_results}
        result = result_by_seed.get(seed)
        if (
            descriptor is None
            or descriptor.logical_type != "seed_result"
            or descriptor.size != record.size
            or result is None
            or result.status is not SeedRunStatus.SUCCESS
            or result.artifact_sha256 != digest
        ):
            raise DiscoveryIntegrityError("seed output is not exactly manifest-admitted")
        value = self._canonical_mapping(content, "seed output")
        if (
            value.get("run_id") != spec.get("run_id")
            or value.get("spec_sha256") != manifest.spec_sha256
            or value.get("dataset_sha256") != proposal.data_sha256
            or value.get("seed") != seed
        ):
            raise DiscoveryIntegrityError("seed output scientific binding is invalid")
        candidate = self._binary_vector(
            value.get("candidate_correctness"), "candidate correctness"
        )
        baseline = self._binary_vector(
            value.get("baseline_correctness"), "baseline correctness"
        )
        if (
            len(candidate) != len(baseline)
            or candidate != expected_candidate
            or baseline != expected_baseline
        ):
            raise DiscoveryIntegrityError(
                "seed correctness differs from dataset/configuration recomputation"
            )
        recomputed_candidate = sum(candidate) / len(candidate)
        recomputed_baseline = sum(baseline) / len(baseline)
        reported_candidate = self._fraction(
            value.get("candidate_accuracy"), "reported candidate accuracy"
        )
        reported_baseline = self._fraction(
            value.get("baseline_accuracy"), "reported baseline accuracy"
        )
        manifest_metric = self._fraction(result.metric, "manifest seed metric")
        if not (
            math.isclose(reported_candidate, recomputed_candidate, rel_tol=0.0, abs_tol=1e-12)
            and math.isclose(reported_baseline, recomputed_baseline, rel_tol=0.0, abs_tol=1e-12)
            and math.isclose(manifest_metric, recomputed_candidate, rel_tol=0.0, abs_tol=1e-12)
        ):
            raise DiscoveryIntegrityError("seed metric differs from reviewed recomputation")
        return (
            SeedObservation(seed, SeedStatus.SUCCESS, recomputed_candidate, digest),
            value,
        )

    def _resolve_ablation_payload(
        self,
        *,
        ablation_id: str,
        digest: str,
        proposal: DiscoveryProposal,
        spec_record: ArtifactRecord,
        spec: Mapping[str, Any],
        manifest_record: ArtifactRecord,
        manifest: OutputManifest,
        baseline_vector: tuple[float, ...],
    ) -> tuple[AblationEvidence, Mapping[str, Any]]:
        record, content = self._require_artifact(
            digest,
            logical_type="experiment_output.ablation_result",
            creator_role=Role.EXPERIMENT_RUNNER,
        )
        if not {spec_record.sha256, manifest_record.sha256}.issubset(
            record.parent_artifacts
        ):
            raise DiscoveryIntegrityError("ablation output lacks direct run custody")
        descriptor = {item.sha256: item for item in manifest.artifacts}.get(digest)
        admitted = {item.ablation_id: item for item in manifest.ablations}.get(
            ablation_id
        )
        if (
            descriptor is None
            or descriptor.logical_type != "ablation_result"
            or descriptor.size != record.size
            or admitted is None
            or admitted.artifact_sha256 != digest
            or admitted.status != "PASS"
        ):
            raise DiscoveryIntegrityError("ablation is not exactly manifest-admitted")
        value = self._canonical_mapping(content, "ablation output")
        if (
            value.get("run_id") != spec.get("run_id")
            or value.get("spec_sha256") != manifest.spec_sha256
            or value.get("dataset_sha256") != proposal.data_sha256
            or value.get("evaluator_sha256") != proposal.evaluator_sha256
            or value.get("ablation_id") != ablation_id
            or value.get("intervention")
            != "replace candidate with frozen constant-zero baseline"
        ):
            raise DiscoveryIntegrityError("ablation scientific binding is invalid")
        vector = self._binary_vector(
            value.get("ablated_correctness"), "ablated correctness"
        )
        reported = self._fraction(value.get("accuracy"), "reported ablation accuracy")
        if not math.isclose(
            reported, sum(vector) / len(vector), rel_tol=0.0, abs_tol=1e-12
        ):
            raise DiscoveryIntegrityError("ablation metric differs from recomputation")
        verified = vector == baseline_vector
        return (
            AblationEvidence(
                ablation_id,
                digest,
                verified,
                proposal.experiment_id,
            ),
            value,
        )

    def _resolve_check(
        self,
        *,
        check: DiscoveryCheck,
        digest: str,
        proposal: DiscoveryProposal,
        registered: RegisteredBranchEvidence,
        required_parents: tuple[str, ...],
        seed_payloads: tuple[Mapping[str, Any], ...],
        ablation_payloads: tuple[Mapping[str, Any], ...],
    ) -> bool | None:
        record, content = self._require_artifact(
            digest,
            logical_type=_CHECK_LOGICAL_TYPES[check],
            creator_role=_CHECK_CREATOR_ROLES[check],
        )
        self._require_ancestry(digest, required_parents)
        value = self._canonical_mapping(content, "discovery check descriptor")
        expected_rules = {
            DiscoveryCheck.CONTROL: "candidate_exceeds_baseline_all_seeds",
            DiscoveryCheck.ROBUSTNESS: (
                "not_applicable_deterministic_fixture_no_promotion_gate"
            ),
            DiscoveryCheck.FALSIFICATION: "ablation_reduces_to_baseline",
        }
        expected_evidence = [
            *(
                registered.seed_output_sha256s[seed]
                for seed in proposal.planned_seeds
            ),
            *(
                registered.ablation_artifact_sha256s[ablation]
                for ablation in proposal.required_ablations
            ),
        ]
        expected = {
            "schema_version": "SCIENTIST_ONE_DISCOVERY_CHECK_V1",
            "check": check.value,
            "source_experiment_id": registered.source_experiment_id,
            "evaluator_sha256": proposal.evaluator_sha256,
            "frozen_run_spec_sha256": registered.frozen_run_spec_sha256,
            "output_manifest_sha256": registered.output_manifest_sha256,
            "evidence_artifact_sha256s": expected_evidence,
            "rule": expected_rules[check],
        }
        if dict(value) != expected:
            raise DiscoveryIntegrityError("discovery check descriptor is not exact")

        candidates = tuple(
            self._binary_vector(item.get("candidate_correctness"), "candidate correctness")
            for item in seed_payloads
        )
        baselines = tuple(
            self._binary_vector(item.get("baseline_correctness"), "baseline correctness")
            for item in seed_payloads
        )
        if check is DiscoveryCheck.CONTROL:
            return all(sum(candidate) > sum(baseline) for candidate, baseline in zip(candidates, baselines))
        if check is DiscoveryCheck.ROBUSTNESS:
            # Repeated deterministic outputs are already required by the seed
            # semantic verifier and do not constitute independent robustness
            # evidence.  Preserve an explicit N/A instead of minting a PASS.
            return None
        ablated = tuple(
            self._binary_vector(item.get("ablated_correctness"), "ablated correctness")
            for item in ablation_payloads
        )
        return (
            bool(ablated)
            and all(vector == baselines[0] for vector in ablated)
            and all(sum(candidate) > sum(vector) for candidate in candidates for vector in ablated)
        )

    def _resolve(
        self,
        branch: "BranchRecord",
        registered: RegisteredBranchEvidence,
    ) -> _ResolvedCheckedEvidence:
        self._verify_resolver_is_pinned()
        proposal = branch.proposal
        if (
            proposal.experiment_id is None
            or proposal.evaluator_sha256 is None
            or proposal.evaluator_implementation_sha256 is None
            or proposal.data_sha256 is None
        ):
            raise DiscoveryError(
                "checked discovery requires experiment, data, and evaluator identities"
            )
        if (
            proposal.experiment_id != registered.source_experiment_id
            or proposal.evaluator_sha256 != self._evaluator_sha256
            or proposal.metric_direction != "maximize"
            or proposal.scientific_fingerprint(branch.parent_snapshot_sha256)
            != branch.scientific_fingerprint
        ):
            raise DiscoveryIntegrityError("checked discovery identity binding mismatch")
        if set(registered.seed_output_sha256s) != set(proposal.planned_seeds):
            raise DiscoveryIntegrityError("checked discovery does not cover every planned seed")
        if set(registered.ablation_artifact_sha256s) != set(
            proposal.required_ablations
        ):
            raise DiscoveryIntegrityError("checked discovery ablation set is not exact")

        code_record, _ = self._require_artifact(
            proposal.code_sha256,
            logical_type="experiment_code",
            creator_role=Role.IMPLEMENTER,
        )
        configuration_record, configuration_bytes = self._require_artifact(
            proposal.configuration_sha256,
            logical_type="experiment_configuration",
            creator_role=Role.PROTOCOL_DESIGNER,
        )
        configuration = self._canonical_mapping(
            configuration_bytes, "experiment configuration"
        )
        data_record, data_bytes = self._require_artifact(
            proposal.data_sha256,
            logical_type="dataset_fixture",
            creator_role=Role.EVIDENCE_CURATOR,
        )
        evaluator_record, evaluator_bytes = self._require_artifact(
            proposal.evaluator_sha256,
            logical_type="metric_evaluator",
            creator_role=Role.PROTOCOL_DESIGNER,
        )
        self._validate_evaluator_contract(evaluator_bytes)
        implementation_record, implementation_bytes = self._require_artifact(
            proposal.evaluator_implementation_sha256,
            logical_type="vnext_source_snapshot",
            creator_role=Role.ORCHESTRATOR,
        )
        self._validate_implementation_contract(implementation_bytes)
        self._require_ancestry(
            configuration_record.sha256,
            (code_record.sha256, data_record.sha256),
        )
        self._require_ancestry(
            evaluator_record.sha256,
            (configuration_record.sha256, code_record.sha256, data_record.sha256),
        )
        (
            spec_record,
            spec,
            _,
            manifest_record,
            manifest,
            binding_record,
            input_binding_record,
            plan_record,
            ledger_event,
        ) = self._resolve_run_custody(branch, registered, configuration)
        self._require_ancestry(
            spec_record.sha256,
            (
                code_record.sha256,
                data_record.sha256,
                configuration_record.sha256,
                evaluator_record.sha256,
                implementation_record.sha256,
            ),
        )
        self._require_ancestry(
            code_record.sha256,
            (implementation_record.sha256,),
        )
        expected_candidate, expected_baseline, expected_method_identity = (
            self._expected_binary_accuracy_vectors(data_bytes, configuration_bytes)
        )
        if (
            proposal.method_identity != expected_method_identity
            or proposal.required_ablations != ("remove-signal",)
        ):
            raise DiscoveryIntegrityError(
                "discovery method or ablation identity is not the reviewed implementation"
            )

        observations: list[SeedObservation] = []
        seed_payloads: list[Mapping[str, Any]] = []
        seed_hashes: list[str] = []
        for seed in proposal.planned_seeds:
            digest = registered.seed_output_sha256s[seed]
            observation, payload = self._resolve_seed_payload(
                seed=seed,
                digest=digest,
                proposal=proposal,
                spec_record=spec_record,
                spec=spec,
                manifest_record=manifest_record,
                manifest=manifest,
                expected_candidate=expected_candidate,
                expected_baseline=expected_baseline,
            )
            observations.append(observation)
            seed_payloads.append(payload)
            seed_hashes.append(digest)

        ablations: list[AblationEvidence] = []
        ablation_payloads: list[Mapping[str, Any]] = []
        ablation_hashes: list[str] = []
        baseline_vector = self._binary_vector(
            seed_payloads[0].get("baseline_correctness"), "baseline correctness"
        )
        for ablation_id in proposal.required_ablations:
            digest = registered.ablation_artifact_sha256s[ablation_id]
            ablation, payload = self._resolve_ablation_payload(
                ablation_id=ablation_id,
                digest=digest,
                proposal=proposal,
                spec_record=spec_record,
                spec=spec,
                manifest_record=manifest_record,
                manifest=manifest,
                baseline_vector=baseline_vector,
            )
            ablations.append(ablation)
            ablation_payloads.append(payload)
            ablation_hashes.append(digest)

        check_results: dict[DiscoveryCheck, bool | None] = {}
        check_hashes: list[str] = []
        evidence_inputs = (*seed_hashes, *ablation_hashes)
        custody_inputs = (
            code_record.sha256,
            data_record.sha256,
            configuration_record.sha256,
            evaluator_record.sha256,
            implementation_record.sha256,
            spec_record.sha256,
            manifest_record.sha256,
            binding_record.sha256,
            input_binding_record.sha256,
            plan_record.sha256,
            *evidence_inputs,
        )
        for check in DiscoveryCheck:
            digest = registered.check_artifact_sha256(check)
            decision = self._resolve_check(
                check=check,
                digest=digest,
                proposal=proposal,
                registered=registered,
                required_parents=custody_inputs,
                seed_payloads=tuple(seed_payloads),
                ablation_payloads=tuple(ablation_payloads),
            )
            check_results[check] = decision
            check_hashes.append(digest)

        evidence = BranchEvidence(
            seed_observations=tuple(observations),
            ablations=tuple(ablations),
            control_passed=check_results[DiscoveryCheck.CONTROL],
            robustness_passed=check_results[DiscoveryCheck.ROBUSTNESS],
            falsification_survived=check_results[DiscoveryCheck.FALSIFICATION],
        )
        parents = (
            code_record.sha256,
            data_record.sha256,
            configuration_record.sha256,
            evaluator_record.sha256,
            implementation_record.sha256,
            spec_record.sha256,
            manifest_record.sha256,
            binding_record.sha256,
            input_binding_record.sha256,
            plan_record.sha256,
            *seed_hashes,
            *ablation_hashes,
            *check_hashes,
        )
        if len(parents) > MAX_ARTIFACT_PARENTS:
            raise DiscoveryError("checked discovery evidence exceeds receipt parent bound")
        payload = {
            "schema_version": "SCIENTIST_ONE_DISCOVERY_CHECKED_RESULT_V1",
            "branch_id": branch.branch_id,
            "proposal_id": proposal.proposal_id,
            "scientific_fingerprint": branch.scientific_fingerprint,
            "source_experiment_id": registered.source_experiment_id,
            "evaluator_sha256": evaluator_record.sha256,
            "evaluator_implementation_id": self._reviewed_evaluator.value,
            "evaluator_implementation_sha256": implementation_record.sha256,
            "ledger_event_id": ledger_event.event_id,
            "ledger_event_hash": ledger_event.event_hash,
            "registered_evidence": registered.to_dict(),
            "evidence": _branch_evidence_payload(evidence),
            "metrics_recomputed": True,
            "control_defaults_used": False,
            "validation_result": "PASS",
        }
        frozen_payload = freeze_json(payload)
        assert isinstance(frozen_payload, Mapping)
        return _ResolvedCheckedEvidence(evidence, frozen_payload, parents)

    def _reject_distinct_evidence_reuse(
        self,
        branch: "BranchRecord",
        registered: RegisteredBranchEvidence,
    ) -> None:
        expected_registered = registered.to_dict()
        try:
            records = self._registry.list_records()
        except Exception as exc:
            raise DiscoveryIntegrityError("discovery receipt inventory is unavailable") from exc
        for record in records:
            if record.logical_type not in {
                "discovery.checked_result_evaluation",
                "discovery.checked_result_rejection",
            }:
                continue
            _, content = self._require_artifact(
                record.sha256,
                logical_type=record.logical_type,
                creator_role=Role.CLAIM_VERIFIER,
            )
            value = self._canonical_mapping(content, "prior discovery receipt")
            if value.get("registered_evidence") != expected_registered:
                continue
            if (
                record.logical_type == "discovery.checked_result_rejection"
                or
                value.get("scientific_fingerprint")
                != branch.scientific_fingerprint
            ):
                raise DiscoveryIntegrityError(
                    "one execution evidence graph cannot authorize a distinct proposal"
                )

    def evaluate_and_register(
        self,
        branch: "BranchRecord",
        registered: RegisteredBranchEvidence,
    ) -> tuple[BranchEvidence, str]:
        self._reject_distinct_evidence_reuse(branch, registered)
        resolved = self._resolve(branch, registered)
        repeated = self._resolve(branch, registered)
        if repeated != resolved:
            raise DiscoveryIntegrityError("checked discovery inputs changed during evaluation")
        receipt = self._registry.put_json(
            thaw_json(resolved.receipt_payload),
            logical_type="discovery.checked_result_evaluation",
            schema_version="1.0",
            mime_type="application/json",
            origin="deterministic registry-backed discovery result evaluation",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "discovery", "evaluate-checked-result"),
            parent_artifacts=resolved.receipt_parents,
            validation_result="PASS",
            frozen=True,
        )
        return resolved.evidence, receipt.sha256

    def register_rejection(
        self,
        branch: "BranchRecord",
        registered: RegisteredBranchEvidence,
        failure: Exception,
    ) -> str:
        """Persist a failed checked attempt without claiming absent parents."""

        self._verify_resolver_is_pinned()
        payload = {
            "schema_version": "SCIENTIST_ONE_DISCOVERY_CHECKED_REJECTION_V1",
            "branch_id": branch.branch_id,
            "proposal_id": branch.proposal.proposal_id,
            "scientific_fingerprint": branch.scientific_fingerprint,
            "registered_evidence": registered.to_dict(),
            "attempt_status": "REJECTED",
            "failure_class": type(failure).__name__,
            "reason_code": "CHECKED_RESULT_RESOLUTION_FAILED",
            "exploration_only": True,
            "scientific_evidence_eligible": False,
        }
        receipt = self._registry.put_json(
            payload,
            logical_type="discovery.checked_result_rejection",
            schema_version="1.0",
            mime_type="application/json",
            origin="fail-closed checked discovery attempt receipt",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "discovery", "reject-checked-result"),
            # A declared missing or corrupt hash is data in the receipt, not a
            # provenance parent.  Never invent parents for unavailable bytes.
            parent_artifacts=(),
            validation_result="PASS",
            frozen=True,
        )
        return receipt.sha256

    def revalidate_rejection(self, branch: "BranchRecord") -> None:
        self._verify_resolver_is_pinned()
        if (
            branch.evidence_authority
            is not DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_INVALIDATED
            or branch.evidence is not None
            or branch.registered_evidence is None
            or branch.evaluation_receipt_sha256 is None
            or branch.promotion_receipt_sha256 is not None
        ):
            raise DiscoveryIntegrityError("branch is not a checked-result rejection")
        record, content = self._require_artifact(
            branch.evaluation_receipt_sha256,
            logical_type="discovery.checked_result_rejection",
            creator_role=Role.CLAIM_VERIFIER,
        )
        value = self._canonical_mapping(content, "checked-result rejection receipt")
        if (
            set(value)
            != {
                "schema_version",
                "branch_id",
                "proposal_id",
                "scientific_fingerprint",
                "registered_evidence",
                "attempt_status",
                "failure_class",
                "reason_code",
                "exploration_only",
                "scientific_evidence_eligible",
            }
            or value.get("schema_version")
            != "SCIENTIST_ONE_DISCOVERY_CHECKED_REJECTION_V1"
            or value.get("branch_id") != branch.branch_id
            or value.get("proposal_id") != branch.proposal.proposal_id
            or value.get("scientific_fingerprint")
            != branch.scientific_fingerprint
            or value.get("registered_evidence")
            != branch.registered_evidence.to_dict()
            or value.get("attempt_status") != "REJECTED"
            or not isinstance(value.get("failure_class"), str)
            or not value["failure_class"]
            or len(value["failure_class"]) > 256
            or value.get("reason_code") != "CHECKED_RESULT_RESOLUTION_FAILED"
            or value.get("exploration_only") is not True
            or value.get("scientific_evidence_eligible") is not False
            or record.parent_artifacts != ()
        ):
            raise DiscoveryIntegrityError("checked-result rejection receipt changed")

    @staticmethod
    def _checked_classification(
        branch: "BranchRecord",
        evidence: BranchEvidence,
    ) -> tuple[BranchStatus, tuple[str, ...], str | None]:
        """Independently recompute the engine's checked-result classification."""

        reasons: list[str] = []
        observed_seeds = tuple(item.seed for item in evidence.seed_observations)
        if len(set(observed_seeds)) != len(observed_seeds):
            reasons.append("DUPLICATE_SEED_REPORT")
        if set(observed_seeds) != set(branch.proposal.planned_seeds):
            reasons.append("INCOMPLETE_ALL_SEED_REPORTING")
        ablation_ids = tuple(item.ablation_id for item in evidence.ablations)
        if len(set(ablation_ids)) != len(ablation_ids):
            reasons.append("DUPLICATE_ABLATION_REPORT")
        ablation_by_id = {item.ablation_id: item for item in evidence.ablations}
        for required in branch.proposal.required_ablations:
            item = ablation_by_id.get(required)
            if item is None:
                reasons.append(f"MISSING_ABLATION:{required}")
            elif not item.verified:
                reasons.append(f"UNVERIFIED_ABLATION:{required}")

        statuses = {item.status for item in evidence.seed_observations}
        if reasons or SeedStatus.INVALID in statuses:
            status = BranchStatus.INVALID
        elif SeedStatus.FAILED in statuses:
            status = BranchStatus.FAILED
        elif SeedStatus.NULL in statuses:
            status = BranchStatus.NULL_RESULT
        elif SeedStatus.NEGATIVE in statuses:
            status = BranchStatus.NEGATIVE_RESULT
        elif statuses == {SeedStatus.SUCCESS} and evidence.seed_observations:
            status = BranchStatus.SUCCEEDED
        else:
            status = BranchStatus.INVALID
            reasons.append("EMPTY_OR_UNKNOWN_SEED_REPORT")
        if not evidence.control_passed:
            status = BranchStatus.INVALID
            reasons.append("CONTROL_FAILED")
        if evidence.robustness_passed is False:
            status = BranchStatus.INVALID
            reasons.append("ROBUSTNESS_FAILED")
        if not evidence.falsification_survived:
            if status is not BranchStatus.INVALID:
                status = BranchStatus.NEGATIVE_RESULT
            reasons.append("FALSIFICATION_NOT_SURVIVED")

        metric_values = [
            Decimal(str(item.metric))
            for item in evidence.seed_observations
            if item.metric is not None
        ]
        aggregate = None
        if metric_values:
            aggregate = str(
                sum(metric_values, Decimal(0)) / Decimal(len(metric_values))
            )
        return status, tuple(reasons), aggregate

    def _validate_checked_branch_state(
        self,
        branch: "BranchRecord",
        evidence: BranchEvidence,
    ) -> None:
        status, reasons, aggregate = self._checked_classification(branch, evidence)
        admitted_statuses = {status}
        if status is BranchStatus.SUCCEEDED:
            admitted_statuses.add(BranchStatus.PROMOTED)
        if (
            branch.status not in admitted_statuses
            or branch.reason_codes != reasons
            or branch.aggregate_metric != aggregate
        ):
            raise DiscoveryIntegrityError(
                "checked branch status, reasons, or aggregate were not recomputed"
            )

    def _promotion_contract(
        self, branch: "BranchRecord"
    ) -> tuple[Mapping[str, Any], tuple[str, ...]]:
        if (
            branch.evidence_authority
            is not DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_VERIFIED
            or branch.registered_evidence is None
            or branch.evaluation_receipt_sha256 is None
            or branch.evidence is None
            or branch.status not in {BranchStatus.SUCCEEDED, BranchStatus.PROMOTED}
        ):
            raise DiscoveryIntegrityError("branch lacks checked promotion authority")
        self.revalidate(branch)
        evaluation_record, _ = self._require_artifact(
            branch.evaluation_receipt_sha256,
            logical_type="discovery.checked_result_evaluation",
            creator_role=Role.CLAIM_VERIFIER,
        )
        ledger_event = self._resolve_ledger_event(branch.registered_evidence)
        parents = (
            branch.evaluation_receipt_sha256,
            *evaluation_record.parent_artifacts,
        )
        if len(parents) != len(set(parents)) or len(parents) > MAX_ARTIFACT_PARENTS:
            raise DiscoveryIntegrityError("promotion custody parent inventory is invalid")
        payload = freeze_json(
            {
                "schema_version": "SCIENTIST_ONE_DISCOVERY_PROMOTION_V1",
                "branch_id": branch.branch_id,
                "proposal_id": branch.proposal.proposal_id,
                "scientific_fingerprint": branch.scientific_fingerprint,
                "evaluation_receipt_sha256": branch.evaluation_receipt_sha256,
                "registered_evidence": branch.registered_evidence.to_dict(),
                "ledger_event_id": ledger_event.event_id,
                "ledger_event_hash": ledger_event.event_hash,
                "decision": "PROMOTED",
                "branch_status": "PROMOTED",
                "evidence_authority": (
                    DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_VERIFIED.value
                ),
                "aggregate_metric": branch.aggregate_metric,
                "exploration_only": True,
                "scientific_evidence_eligible": False,
                "validation_result": "PASS",
            }
        )
        assert isinstance(payload, Mapping)
        return payload, parents

    def register_promotion(self, branch: "BranchRecord") -> str:
        payload, parents = self._promotion_contract(branch)
        repeated_payload, repeated_parents = self._promotion_contract(branch)
        if payload != repeated_payload or parents != repeated_parents:
            raise DiscoveryIntegrityError("promotion custody changed during registration")
        receipt = self._registry.put_json(
            thaw_json(payload),
            logical_type="discovery.branch_promotion",
            schema_version="1.0",
            mime_type="application/json",
            origin="freshly re-resolved exploratory discovery promotion",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "discovery", "promote-checked-branch"),
            parent_artifacts=parents,
            validation_result="PASS",
            frozen=True,
        )
        return receipt.sha256

    def register_promotion_rejection(
        self,
        branch: "BranchRecord",
        failure: Exception,
    ) -> str:
        """Persist a failed promotion re-resolution without trusting its inputs."""

        self._verify_resolver_is_pinned()
        if (
            branch.registered_evidence is None
            or branch.evaluation_receipt_sha256 is None
        ):
            raise DiscoveryIntegrityError(
                "promotion rejection lacks declared evaluation custody"
            )
        receipt = self._registry.put_json(
            {
                "schema_version": "SCIENTIST_ONE_DISCOVERY_PROMOTION_REJECTION_V1",
                "branch_id": branch.branch_id,
                "proposal_id": branch.proposal.proposal_id,
                "scientific_fingerprint": branch.scientific_fingerprint,
                "evaluation_receipt_sha256": branch.evaluation_receipt_sha256,
                "registered_evidence": branch.registered_evidence.to_dict(),
                "decision": "REJECTED",
                "failure_class": type(failure).__name__,
                "reason_code": "CHECKED_EVIDENCE_REVALIDATION_FAILED",
                "exploration_only": True,
                "scientific_evidence_eligible": False,
            },
            logical_type="discovery.branch_promotion_rejection",
            schema_version="1.0",
            mime_type="application/json",
            origin="fail-closed discovery promotion rejection receipt",
            creator_role=Role.CLAIM_VERIFIER,
            creation_command=("scientist-one", "discovery", "reject-promotion"),
            # The failed evaluation/custody object may be absent or corrupt.
            # Retain its declared digest in payload, never as an invented parent.
            parent_artifacts=(),
            validation_result="PASS",
            frozen=True,
        )
        return receipt.sha256

    def revalidate(self, branch: "BranchRecord") -> None:
        if (
            branch.registered_evidence is None
            or branch.evaluation_receipt_sha256 is None
            or branch.evidence is None
        ):
            raise DiscoveryIntegrityError("checked branch lacks revalidation inputs")
        resolved = self._resolve(branch, branch.registered_evidence)
        record, content = self._require_artifact(
            branch.evaluation_receipt_sha256,
            logical_type="discovery.checked_result_evaluation",
            creator_role=Role.CLAIM_VERIFIER,
        )
        expected = canonical_json_bytes(thaw_json(resolved.receipt_payload)) + b"\n"
        if (
            resolved.evidence != branch.evidence
            or content != expected
            or record.parent_artifacts != resolved.receipt_parents
            or hashlib.sha256(expected).hexdigest() != branch.evaluation_receipt_sha256
        ):
            raise DiscoveryIntegrityError("checked discovery receipt or semantics changed")
        self._validate_checked_branch_state(branch, resolved.evidence)

    def revalidate_promotion(self, branch: "BranchRecord") -> None:
        if branch.promotion_receipt_sha256 is None:
            raise DiscoveryIntegrityError("promoted branch lacks promotion receipt")
        payload, parents = self._promotion_contract(branch)
        record, content = self._require_artifact(
            branch.promotion_receipt_sha256,
            logical_type="discovery.branch_promotion",
            creator_role=Role.CLAIM_VERIFIER,
        )
        expected = canonical_json_bytes(thaw_json(payload)) + b"\n"
        if (
            content != expected
            or record.parent_artifacts != parents
            or hashlib.sha256(expected).hexdigest()
            != branch.promotion_receipt_sha256
        ):
            raise DiscoveryIntegrityError("discovery promotion receipt changed")

    def revalidate_promotion_rejection(self, branch: "BranchRecord") -> None:
        self._verify_resolver_is_pinned()
        if (
            branch.evidence_authority
            is not DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_INVALIDATED
            or branch.registered_evidence is None
            or branch.evaluation_receipt_sha256 is None
            or branch.promotion_receipt_sha256 is None
        ):
            raise DiscoveryIntegrityError("branch is not a promotion rejection")
        record, content = self._require_artifact(
            branch.promotion_receipt_sha256,
            logical_type="discovery.branch_promotion_rejection",
            creator_role=Role.CLAIM_VERIFIER,
        )
        value = self._canonical_mapping(content, "promotion rejection receipt")
        if (
            set(value)
            != {
                "schema_version",
                "branch_id",
                "proposal_id",
                "scientific_fingerprint",
                "evaluation_receipt_sha256",
                "registered_evidence",
                "decision",
                "failure_class",
                "reason_code",
                "exploration_only",
                "scientific_evidence_eligible",
            }
            or value.get("schema_version")
            != "SCIENTIST_ONE_DISCOVERY_PROMOTION_REJECTION_V1"
            or value.get("branch_id") != branch.branch_id
            or value.get("proposal_id") != branch.proposal.proposal_id
            or value.get("scientific_fingerprint")
            != branch.scientific_fingerprint
            or value.get("evaluation_receipt_sha256")
            != branch.evaluation_receipt_sha256
            or value.get("registered_evidence")
            != branch.registered_evidence.to_dict()
            or value.get("decision") != "REJECTED"
            or not isinstance(value.get("failure_class"), str)
            or not value["failure_class"]
            or len(value["failure_class"]) > 256
            or value.get("reason_code")
            != "CHECKED_EVIDENCE_REVALIDATION_FAILED"
            or value.get("exploration_only") is not True
            or value.get("scientific_evidence_eligible") is not False
            or record.parent_artifacts != ()
        ):
            raise DiscoveryIntegrityError("promotion rejection receipt changed")


@dataclass(frozen=True)
class BranchRecord:
    branch_id: str
    proposal: DiscoveryProposal
    scientific_fingerprint: str
    parent_snapshot_sha256: str | None
    status: BranchStatus
    selection_index: int
    evidence: BranchEvidence | None = None
    duplicate_of: str | None = None
    reason_codes: tuple[str, ...] = ()
    aggregate_metric: str | None = None
    evidence_authority: DiscoveryEvidenceAuthority = DiscoveryEvidenceAuthority.NONE
    registered_evidence: RegisteredBranchEvidence | None = None
    evaluation_receipt_sha256: str | None = None
    promotion_receipt_sha256: str | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.branch_id, "branch ID")
        validate_sha256(self.scientific_fingerprint, "scientific fingerprint")
        if self.parent_snapshot_sha256 is not None:
            validate_sha256(self.parent_snapshot_sha256, "parent snapshot SHA-256")
        if self.duplicate_of is not None:
            validate_identifier(self.duplicate_of, "duplicate branch ID")
        if not isinstance(self.status, BranchStatus):
            raise DiscoveryError("branch status must be typed")
        if self.selection_index < 1:
            raise DiscoveryError("selection index must be positive")
        if not isinstance(self.evidence_authority, DiscoveryEvidenceAuthority):
            raise DiscoveryError("branch evidence authority must be typed")
        if self.evaluation_receipt_sha256 is not None:
            validate_sha256(
                self.evaluation_receipt_sha256,
                "discovery evaluation receipt SHA-256",
            )
        if self.promotion_receipt_sha256 is not None:
            validate_sha256(
                self.promotion_receipt_sha256,
                "discovery promotion receipt SHA-256",
            )
        if self.evidence_authority is DiscoveryEvidenceAuthority.NONE:
            if (
                self.evidence is not None
                or self.registered_evidence is not None
                or self.evaluation_receipt_sha256 is not None
                or self.promotion_receipt_sha256 is not None
            ):
                raise DiscoveryError("unevaluated branch cannot carry evidence")
        elif self.evidence_authority is DiscoveryEvidenceAuthority.DIAGNOSTIC_ONLY:
            if (
                self.evidence is None
                or self.registered_evidence is not None
                or self.evaluation_receipt_sha256 is not None
                or self.promotion_receipt_sha256 is not None
            ):
                raise DiscoveryError("diagnostic branch evidence contract is inconsistent")
        elif self.evidence_authority is DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_VERIFIED:
            if (
                self.evidence is None
                or not isinstance(self.registered_evidence, RegisteredBranchEvidence)
                or self.evaluation_receipt_sha256 is None
            ):
                raise DiscoveryError("checked branch evidence contract is incomplete")
        elif self.evidence_authority is DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_INVALIDATED:
            if (
                not isinstance(self.registered_evidence, RegisteredBranchEvidence)
                or self.evaluation_receipt_sha256 is None
            ):
                raise DiscoveryError("invalid checked attempt lacks its rejection receipt")
        else:  # pragma: no cover - exhaustive enum protection
            raise DiscoveryError("unknown discovery evidence authority")
        if (
            self.status is BranchStatus.PROMOTED
            and self.evidence_authority
            is not DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_VERIFIED
        ):
            raise DiscoveryError("only registry-evaluator-verified evidence may be promoted")
        if self.status is BranchStatus.PROMOTED and self.promotion_receipt_sha256 is None:
            raise DiscoveryError("promoted branch requires a frozen promotion receipt")
        if (
            self.status is not BranchStatus.PROMOTED
            and self.promotion_receipt_sha256 is not None
            and self.evidence_authority
            is not DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_INVALIDATED
        ):
            raise DiscoveryError("non-promoted branch cannot carry a promotion receipt")

    @property
    def retained(self) -> bool:
        """All branch outcomes are retained, including rejected and invalid ones."""

        return True

    @property
    def _structurally_promotion_eligible(self) -> bool:
        """Cached shape only; authoritative eligibility is an engine read."""

        return (
            self.status in {BranchStatus.SUCCEEDED, BranchStatus.PROMOTED}
            and self.evidence_authority
            is DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_VERIFIED
            and self.registered_evidence is not None
            and self.evaluation_receipt_sha256 is not None
        )


@dataclass(frozen=True)
class SelectionEvent:
    index: int
    action: DiscoveryAction
    decision: SelectionDecision
    proposal_id: str | None
    branch_id: str | None
    reason_codes: tuple[str, ...]
    compute_units_used: int
    branch_count: int
    considered_proposal_ids: tuple[str, ...] = ()


def _sha256_json(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class DiscoveryEngine:
    """Append-only in-memory discovery state with deterministic decisions."""

    _NEW_BRANCH_ACTIONS = frozenset(
        {
            DiscoveryAction.FRESH_IDEA,
            DiscoveryAction.INDEPENDENT_BRANCH,
            DiscoveryAction.REFINE_BRANCH,
            DiscoveryAction.DEBUG_BRANCH,
            DiscoveryAction.ABLATE,
            DiscoveryAction.RUN_CONTROL,
            DiscoveryAction.RUN_ROBUSTNESS,
            DiscoveryAction.RUN_FALSIFICATION,
        }
    )
    _PARENT_REQUIRED = frozenset(
        {
            DiscoveryAction.REFINE_BRANCH,
            DiscoveryAction.DEBUG_BRANCH,
            DiscoveryAction.ABLATE,
            DiscoveryAction.RUN_CONTROL,
            DiscoveryAction.RUN_ROBUSTNESS,
            DiscoveryAction.RUN_FALSIFICATION,
        }
    )

    def __init__(
        self,
        budget: DiscoveryBudget,
        *,
        evidence_resolver: RegistryDiscoveryEvidenceResolver | None = None,
    ) -> None:
        if not isinstance(budget, DiscoveryBudget):
            raise DiscoveryError("budget must be a DiscoveryBudget")
        if evidence_resolver is not None and type(
            evidence_resolver
        ) is not RegistryDiscoveryEvidenceResolver:
            raise DiscoveryError(
                "evidence_resolver must be an exact RegistryDiscoveryEvidenceResolver"
            )
        self._budget = budget
        self._evidence_resolver = evidence_resolver
        self._admitted_evidence_resolver = evidence_resolver
        self._resolver_dispatch = (
            tuple(
                getattr(RegistryDiscoveryEvidenceResolver, name)
                for name in _RESOLVER_SECURITY_METHODS
            )
            if evidence_resolver is not None
            else None
        )
        self._branches: list[BranchRecord] = []
        self._branch_index: dict[str, int] = {}
        self._fingerprints: dict[str, str] = {}
        self._history: list[SelectionEvent] = []
        self._compute_units_used = 0
        self._accepted_actions = 0

    def _verify_resolver_dispatch(self) -> None:
        if self._evidence_resolver is not self._admitted_evidence_resolver:
            raise DiscoveryIntegrityError("discovery evidence resolver changed")
        if self._evidence_resolver is None:
            return
        if type(self._evidence_resolver) is not RegistryDiscoveryEvidenceResolver:
            raise DiscoveryIntegrityError("discovery evidence resolver type changed")
        current = tuple(
            getattr(RegistryDiscoveryEvidenceResolver, name)
            for name in _RESOLVER_SECURITY_METHODS
        )
        if current != self._resolver_dispatch:
            raise DiscoveryIntegrityError("discovery evidence resolver dispatch changed")

    @property
    def budget(self) -> DiscoveryBudget:
        return self._budget

    @property
    def branches(self) -> tuple[BranchRecord, ...]:
        self._revalidate_promoted_branches()
        return tuple(self._branches)

    @property
    def selection_history(self) -> tuple[SelectionEvent, ...]:
        self._revalidate_promoted_branches()
        return tuple(self._history)

    @property
    def compute_units_used(self) -> int:
        return self._compute_units_used

    def _lookup_branch(self, branch_id: str) -> BranchRecord:
        validate_identifier(branch_id, "branch ID")
        try:
            return self._branches[self._branch_index[branch_id]]
        except KeyError as exc:
            raise DiscoveryError("unknown branch") from exc

    def _revalidate_promoted_branches(self) -> None:
        authoritative = tuple(
            branch
            for branch in self._branches
            if branch.evidence_authority
            in {
                DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_VERIFIED,
                DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_INVALIDATED,
            }
        )
        if not authoritative:
            return
        self._verify_resolver_dispatch()
        if self._evidence_resolver is None:
            raise DiscoveryIntegrityError("promoted branch lost its evidence resolver")
        for branch in authoritative:
            if (
                branch.evidence_authority
                is DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_INVALIDATED
            ):
                if branch.promotion_receipt_sha256 is None:
                    self._evidence_resolver.revalidate_rejection(branch)
                else:
                    self._evidence_resolver.revalidate_promotion_rejection(branch)
            elif branch.status is BranchStatus.PROMOTED:
                self._evidence_resolver.revalidate_promotion(branch)
            else:
                self._evidence_resolver.revalidate(branch)

    def get_branch(self, branch_id: str) -> BranchRecord:
        branch = self._lookup_branch(branch_id)
        if (
            branch.evidence_authority
            in {
                DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_VERIFIED,
                DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_INVALIDATED,
            }
        ):
            self._revalidate_promoted_branches()
        return branch

    def is_promotion_eligible(self, branch_id: str) -> bool:
        """Freshly revalidate and report checked promotion eligibility."""

        return self.get_branch(branch_id)._structurally_promotion_eligible

    def _branch_snapshot_sha256(self, branch: BranchRecord) -> str:
        evidence = (
            _branch_evidence_payload(branch.evidence)
            if branch.evidence is not None
            else None
        )
        return _sha256_json(
            {
                "branch_id": branch.branch_id,
                "scientific_fingerprint": branch.scientific_fingerprint,
                "status": branch.status.value,
                "evidence": evidence,
                "evidence_authority": branch.evidence_authority.value,
                "registered_evidence": (
                    branch.registered_evidence.to_dict()
                    if branch.registered_evidence is not None
                    else None
                ),
                "evaluation_receipt_sha256": branch.evaluation_receipt_sha256,
                "promotion_receipt_sha256": branch.promotion_receipt_sha256,
                "reason_codes": list(branch.reason_codes),
                "aggregate_metric": branch.aggregate_metric,
            }
        )

    def _fingerprint(
        self, proposal: DiscoveryProposal, parent_snapshot_sha256: str | None
    ) -> str:
        return proposal.scientific_fingerprint(parent_snapshot_sha256)

    def _next_branch_id(self, fingerprint: str) -> str:
        return f"branch-{len(self._branches) + 1:04d}-{fingerprint[:12]}"

    def _record_event(
        self,
        *,
        action: DiscoveryAction,
        decision: SelectionDecision,
        proposal_id: str | None,
        branch_id: str | None,
        reason_codes: tuple[str, ...],
        considered_proposal_ids: tuple[str, ...] = (),
    ) -> SelectionEvent:
        event = SelectionEvent(
            index=len(self._history) + 1,
            action=action,
            decision=decision,
            proposal_id=proposal_id,
            branch_id=branch_id,
            reason_codes=reason_codes,
            compute_units_used=self._compute_units_used,
            branch_count=len(self._branches),
            considered_proposal_ids=considered_proposal_ids,
        )
        self._history.append(event)
        return event

    def _append_branch(self, branch: BranchRecord) -> BranchRecord:
        if branch.branch_id in self._branch_index:
            raise DiscoveryIntegrityError("branch identity collision")
        self._branch_index[branch.branch_id] = len(self._branches)
        self._branches.append(branch)
        return branch

    def submit(
        self,
        proposal: DiscoveryProposal,
        *,
        considered_proposal_ids: tuple[str, ...] = (),
    ) -> BranchRecord:
        """Consider one proposal and retain either the branch or its rejection."""

        if not isinstance(proposal, DiscoveryProposal):
            raise DiscoveryError("proposal must be a DiscoveryProposal")
        parent_snapshot: str | None = None
        parent: BranchRecord | None = None
        if proposal.parent_branch_id is not None:
            parent = self.get_branch(proposal.parent_branch_id)
            parent_snapshot = self._branch_snapshot_sha256(parent)
        fingerprint = self._fingerprint(proposal, parent_snapshot)
        branch_id = self._next_branch_id(fingerprint)

        reason_codes: tuple[str, ...] = ()
        decision = SelectionDecision.SELECTED
        duplicate_of: str | None = None
        accepted = True
        if proposal.action not in self._NEW_BRANCH_ACTIONS:
            accepted = False
            decision = SelectionDecision.INVALID_ACTION_REJECTED
            reason_codes = ("ACTION_REQUIRES_EXISTING_BRANCH_OPERATION",)
        elif proposal.action in self._PARENT_REQUIRED and parent is None:
            accepted = False
            decision = SelectionDecision.INVALID_ACTION_REJECTED
            reason_codes = ("PARENT_BRANCH_REQUIRED",)
        elif proposal.action in {DiscoveryAction.FRESH_IDEA, DiscoveryAction.INDEPENDENT_BRANCH} and parent is not None:
            accepted = False
            decision = SelectionDecision.INVALID_ACTION_REJECTED
            reason_codes = ("INDEPENDENT_ACTION_CANNOT_INHERIT_PARENT",)
        elif proposal.confirmatory_compute_units != 0:
            accepted = False
            decision = SelectionDecision.CONFIRMATORY_RESOURCE_REJECTED
            reason_codes = ("CONFIRMATORY_RESOURCES_FORBIDDEN_IN_DISCOVERY",)
        elif fingerprint in self._fingerprints:
            accepted = False
            decision = SelectionDecision.DUPLICATE_SUPPRESSED
            duplicate_of = self._fingerprints[fingerprint]
            reason_codes = ("DUPLICATE_SCIENTIFIC_IDENTITY",)
        elif (
            len([item for item in self._branches if item.status != BranchStatus.REJECTED])
            >= self._budget.maximum_branches
            or self._accepted_actions >= self._budget.maximum_actions
            or self._compute_units_used + proposal.compute_units
            > self._budget.maximum_compute_units
        ):
            accepted = False
            decision = SelectionDecision.BUDGET_REJECTED
            reason_codes = ("EXPLORATORY_BUDGET_EXHAUSTED",)

        branch = BranchRecord(
            branch_id=branch_id,
            proposal=proposal,
            scientific_fingerprint=fingerprint,
            parent_snapshot_sha256=parent_snapshot,
            status=BranchStatus.ACTIVE if accepted else BranchStatus.REJECTED,
            selection_index=len(self._history) + 1,
            duplicate_of=duplicate_of,
            reason_codes=reason_codes,
        )
        self._append_branch(branch)
        if accepted:
            self._fingerprints[fingerprint] = branch_id
            self._compute_units_used += proposal.compute_units
            self._accepted_actions += 1
        self._record_event(
            action=proposal.action,
            decision=decision,
            proposal_id=proposal.proposal_id,
            branch_id=branch_id,
            reason_codes=reason_codes,
            considered_proposal_ids=considered_proposal_ids,
        )
        return branch

    @staticmethod
    def _proposal_priority(proposal: DiscoveryProposal) -> tuple[Any, ...]:
        # Integer fields and lexical tie-breakers make the choice deterministic
        # across processes and Python hash seeds.
        return (
            -proposal.expected_information_value,
            -proposal.scientific_importance,
            -proposal.uncertainty_reduction,
            proposal.compute_units,
            hashlib.sha256(canonical_json_bytes(proposal.identity_payload())).hexdigest(),
            proposal.proposal_id,
        )

    def select_next(self, proposals: Iterable[DiscoveryProposal]) -> BranchRecord | None:
        values = tuple(proposals)
        if not values:
            return None
        if len(values) > MAX_DISCOVERY_BRANCHES:
            raise DiscoveryError("proposal collection exceeds safety bound")
        if not all(isinstance(item, DiscoveryProposal) for item in values):
            raise DiscoveryError("proposal collection must be typed")
        ordered = tuple(sorted(values, key=self._proposal_priority))
        considered = tuple(item.proposal_id for item in ordered)
        for proposal in ordered:
            branch = self.submit(proposal, considered_proposal_ids=considered)
            if branch.status == BranchStatus.ACTIVE:
                return branch
        return None

    def _replace_branch(self, branch: BranchRecord) -> BranchRecord:
        try:
            index = self._branch_index[branch.branch_id]
        except KeyError as exc:  # pragma: no cover - internal invariant
            raise DiscoveryIntegrityError("branch index lost") from exc
        self._branches[index] = branch
        return branch

    @staticmethod
    def _classify_result(
        branch: BranchRecord,
        evidence: BranchEvidence,
    ) -> tuple[BranchStatus, tuple[str, ...], str | None]:
        reasons: list[str] = []
        observed_seeds = tuple(item.seed for item in evidence.seed_observations)
        if len(set(observed_seeds)) != len(observed_seeds):
            reasons.append("DUPLICATE_SEED_REPORT")
        if set(observed_seeds) != set(branch.proposal.planned_seeds):
            reasons.append("INCOMPLETE_ALL_SEED_REPORTING")
        ablation_ids = tuple(item.ablation_id for item in evidence.ablations)
        if len(set(ablation_ids)) != len(ablation_ids):
            reasons.append("DUPLICATE_ABLATION_REPORT")
        ablation_by_id = {item.ablation_id: item for item in evidence.ablations}
        for required in branch.proposal.required_ablations:
            item = ablation_by_id.get(required)
            if item is None:
                reasons.append(f"MISSING_ABLATION:{required}")
            elif not item.verified:
                reasons.append(f"UNVERIFIED_ABLATION:{required}")

        statuses = {item.status for item in evidence.seed_observations}
        if reasons or SeedStatus.INVALID in statuses:
            status = BranchStatus.INVALID
        elif SeedStatus.FAILED in statuses:
            status = BranchStatus.FAILED
        elif SeedStatus.NULL in statuses:
            status = BranchStatus.NULL_RESULT
        elif SeedStatus.NEGATIVE in statuses:
            status = BranchStatus.NEGATIVE_RESULT
        elif statuses == {SeedStatus.SUCCESS} and evidence.seed_observations:
            status = BranchStatus.SUCCEEDED
        else:
            status = BranchStatus.INVALID
            reasons.append("EMPTY_OR_UNKNOWN_SEED_REPORT")
        if not evidence.control_passed:
            status = BranchStatus.INVALID
            reasons.append("CONTROL_FAILED")
        if evidence.robustness_passed is False:
            status = BranchStatus.INVALID
            reasons.append("ROBUSTNESS_FAILED")
        if not evidence.falsification_survived:
            if status is not BranchStatus.INVALID:
                status = BranchStatus.NEGATIVE_RESULT
            reasons.append("FALSIFICATION_NOT_SURVIVED")

        metric_values = [
            Decimal(str(item.metric))
            for item in evidence.seed_observations
            if item.metric is not None
        ]
        aggregate = None
        if metric_values:
            aggregate = str(sum(metric_values, Decimal(0)) / Decimal(len(metric_values)))
        return status, tuple(reasons), aggregate

    def _record_evaluated_result(
        self,
        branch: BranchRecord,
        evidence: BranchEvidence,
        *,
        authority: DiscoveryEvidenceAuthority,
        registered_evidence: RegisteredBranchEvidence | None = None,
        evaluation_receipt_sha256: str | None = None,
        additional_reason_codes: tuple[str, ...] = (),
    ) -> BranchRecord:
        status, reasons, aggregate = self._classify_result(branch, evidence)
        updated = replace(
            branch,
            status=status,
            evidence=evidence,
            reason_codes=(*additional_reason_codes, *reasons),
            aggregate_metric=aggregate,
            evidence_authority=authority,
            registered_evidence=registered_evidence,
            evaluation_receipt_sha256=evaluation_receipt_sha256,
        )
        self._replace_branch(updated)
        self._record_event(
            action=branch.proposal.action,
            decision=SelectionDecision.RESULT_RECORDED,
            proposal_id=branch.proposal.proposal_id,
            branch_id=branch.branch_id,
            reason_codes=updated.reason_codes or (status.value,),
        )
        return updated

    def record_result(self, branch_id: str, evidence: BranchEvidence) -> BranchRecord:
        """Retain caller-declared diagnostics without granting promotion authority.

        This compatibility API never treats SHA-shaped values, metrics, ablation
        flags, or default-true controls as verified scientific evidence.  Use
        :meth:`record_checked_result` for a promotion-capable result.
        """

        branch = self.get_branch(branch_id)
        if branch.status != BranchStatus.ACTIVE:
            raise DiscoveryError("results may only be recorded for an active branch")
        if not isinstance(evidence, BranchEvidence):
            raise DiscoveryError("evidence must be BranchEvidence")
        return self._record_evaluated_result(
            branch,
            evidence,
            authority=DiscoveryEvidenceAuthority.DIAGNOSTIC_ONLY,
            additional_reason_codes=("NON_AUTHORITATIVE_DIAGNOSTIC_RESULT",),
        )

    def record_checked_result(
        self,
        branch_id: str,
        registered_evidence: RegisteredBranchEvidence,
    ) -> BranchRecord:
        """Recompute and retain a registry/evaluator-backed branch result."""

        branch = self.get_branch(branch_id)
        if branch.status != BranchStatus.ACTIVE:
            raise DiscoveryError("results may only be recorded for an active branch")
        if not isinstance(registered_evidence, RegisteredBranchEvidence):
            raise DiscoveryError("registered evidence must be typed")
        if self._evidence_resolver is None:
            raise DiscoveryError("checked result ingestion requires a pinned resolver")
        self._verify_resolver_dispatch()
        try:
            evidence, receipt_sha256 = self._evidence_resolver.evaluate_and_register(
                branch,
                registered_evidence,
            )
        except Exception as exc:
            rejection_sha256 = self._evidence_resolver.register_rejection(
                branch,
                registered_evidence,
                exc,
            )
            invalidated = replace(
                branch,
                status=BranchStatus.INVALID,
                reason_codes=("CHECKED_RESULT_RESOLUTION_FAILED",),
                evidence_authority=(
                    DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_INVALIDATED
                ),
                registered_evidence=registered_evidence,
                evaluation_receipt_sha256=rejection_sha256,
            )
            self._replace_branch(invalidated)
            self._record_event(
                action=branch.proposal.action,
                decision=SelectionDecision.RESULT_RECORDED,
                proposal_id=branch.proposal.proposal_id,
                branch_id=branch.branch_id,
                reason_codes=("CHECKED_RESULT_RESOLUTION_FAILED",),
            )
            return invalidated
        return self._record_evaluated_result(
            branch,
            evidence,
            authority=DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_VERIFIED,
            registered_evidence=registered_evidence,
            evaluation_receipt_sha256=receipt_sha256,
        )

    def ranked_candidates(self) -> tuple[BranchRecord, ...]:
        """Return all retained branches in a deterministic scientific order."""

        self._revalidate_promoted_branches()

        def key(branch: BranchRecord) -> tuple[Any, ...]:
            eligible_rank = (
                0 if branch._structurally_promotion_eligible else 1
            )
            metric = Decimal(branch.aggregate_metric) if branch.aggregate_metric is not None else Decimal(0)
            if branch.proposal.metric_direction == "maximize":
                metric = -metric
            return (eligible_rank, metric, branch.scientific_fingerprint, branch.branch_id)

        return tuple(sorted(self._branches, key=key))

    def promote(self, branch_id: str) -> BranchRecord:
        branch = self._lookup_branch(branch_id)
        if branch.status is BranchStatus.PROMOTED:
            self._verify_resolver_dispatch()
            if self._evidence_resolver is None:
                raise DiscoveryIntegrityError(
                    "promoted branch lost its pinned evidence resolver"
                )
            self._evidence_resolver.revalidate_promotion(branch)
            return branch
        if branch._structurally_promotion_eligible:
            try:
                self._verify_resolver_dispatch()
                if self._evidence_resolver is None:
                    raise DiscoveryIntegrityError(
                        "checked branch lost its pinned evidence resolver"
                    )
                promotion_receipt_sha256 = (
                    self._evidence_resolver.register_promotion(branch)
                )
            except Exception as exc:
                if self._evidence_resolver is None:
                    raise
                rejection_receipt_sha256 = (
                    self._evidence_resolver.register_promotion_rejection(
                        branch,
                        exc,
                    )
                )
                invalidated = replace(
                    branch,
                    status=BranchStatus.INVALID,
                    evidence_authority=(
                        DiscoveryEvidenceAuthority.REGISTRY_EVALUATOR_INVALIDATED
                    ),
                    reason_codes=(
                        *branch.reason_codes,
                        "CHECKED_EVIDENCE_REVALIDATION_FAILED",
                    ),
                    promotion_receipt_sha256=rejection_receipt_sha256,
                )
                self._replace_branch(invalidated)
                self._record_event(
                    action=DiscoveryAction.PROMOTE_CANDIDATE,
                    decision=SelectionDecision.PROMOTION_REJECTED,
                    proposal_id=branch.proposal.proposal_id,
                    branch_id=branch_id,
                    reason_codes=("CHECKED_EVIDENCE_REVALIDATION_FAILED",),
                )
                return invalidated
        if not branch._structurally_promotion_eligible:
            self._record_event(
                action=DiscoveryAction.PROMOTE_CANDIDATE,
                decision=SelectionDecision.PROMOTION_REJECTED,
                proposal_id=branch.proposal.proposal_id,
                branch_id=branch_id,
                reason_codes=(
                    "BRANCH_NOT_SCIENTIFICALLY_ELIGIBLE",
                    branch.status.value,
                    branch.evidence_authority.value,
                ),
            )
            return branch
        updated = replace(
            branch,
            status=BranchStatus.PROMOTED,
            promotion_receipt_sha256=promotion_receipt_sha256,
        )
        self._replace_branch(updated)
        self._record_event(
            action=DiscoveryAction.PROMOTE_CANDIDATE,
            decision=SelectionDecision.PROMOTED,
            proposal_id=branch.proposal.proposal_id,
            branch_id=branch_id,
            reason_codes=("ALL_APPLICABLE_SEEDS_AND_REQUIRED_CHECKS_VALID",),
        )
        return updated

    def terminate(self, branch_id: str, reason: str) -> BranchRecord:
        branch = self.get_branch(branch_id)
        if branch.status == BranchStatus.PROMOTED:
            raise DiscoveryError("a promoted branch cannot be silently terminated")
        if not isinstance(reason, str) or not reason.strip() or len(reason.encode("utf-8")) > 4_096:
            raise DiscoveryError("termination reason must be bounded non-empty text")
        if branch.status == BranchStatus.TERMINATED:
            return branch
        updated = replace(
            branch,
            status=BranchStatus.TERMINATED,
            reason_codes=(*branch.reason_codes, f"TERMINATED:{reason}"),
        )
        self._replace_branch(updated)
        self._record_event(
            action=DiscoveryAction.TERMINATE_BRANCH,
            decision=SelectionDecision.TERMINATED,
            proposal_id=branch.proposal.proposal_id,
            branch_id=branch_id,
            reason_codes=(reason,),
        )
        return updated

    def snapshot(self) -> Mapping[str, Any]:
        """Return an immutable, ledger-ready projection of discovery state."""

        self._revalidate_promoted_branches()

        value = {
            "schema_version": "SCIENTIST_ONE_DISCOVERY_V2",
            "budget": {
                "maximum_branches": self._budget.maximum_branches,
                "maximum_actions": self._budget.maximum_actions,
                "maximum_compute_units": self._budget.maximum_compute_units,
                "confirmatory_compute_units": 0,
            },
            "compute_units_used": self._compute_units_used,
            "branches": [
                {
                    "branch_id": branch.branch_id,
                    "proposal_id": branch.proposal.proposal_id,
                    "action": branch.proposal.action.value,
                    "scientific_fingerprint": branch.scientific_fingerprint,
                    "parent_snapshot_sha256": branch.parent_snapshot_sha256,
                    "status": branch.status.value,
                    "duplicate_of": branch.duplicate_of,
                    "reason_codes": list(branch.reason_codes),
                    "aggregate_metric": branch.aggregate_metric,
                    "evidence": (
                        _branch_evidence_payload(branch.evidence)
                        if branch.evidence is not None
                        else None
                    ),
                    "evidence_authority": branch.evidence_authority.value,
                    "registered_evidence": (
                        branch.registered_evidence.to_dict()
                        if branch.registered_evidence is not None
                        else None
                    ),
                    "evaluation_receipt_sha256": branch.evaluation_receipt_sha256,
                    "promotion_receipt_sha256": branch.promotion_receipt_sha256,
                    "retained": True,
                }
                for branch in self._branches
            ],
            "selection_history": [
                {
                    "index": event.index,
                    "action": event.action.value,
                    "decision": event.decision.value,
                    "proposal_id": event.proposal_id,
                    "branch_id": event.branch_id,
                    "reason_codes": list(event.reason_codes),
                    "compute_units_used": event.compute_units_used,
                    "branch_count": event.branch_count,
                    "considered_proposal_ids": list(event.considered_proposal_ids),
                }
                for event in self._history
            ],
        }
        frozen = freeze_json(value)
        assert isinstance(frozen, Mapping)
        return frozen


__all__ = [
    "AblationEvidence",
    "BranchEvidence",
    "BranchRecord",
    "BranchStatus",
    "DiscoveryAction",
    "DiscoveryBudget",
    "DiscoveryCheck",
    "DiscoveryEngine",
    "DiscoveryEvidenceAuthority",
    "DiscoveryError",
    "DiscoveryIntegrityError",
    "DiscoveryProposal",
    "RegisteredBranchEvidence",
    "RegistryDiscoveryEvidenceResolver",
    "ReviewedDiscoveryEvaluator",
    "SeedObservation",
    "SeedStatus",
    "SelectionDecision",
    "SelectionEvent",
]
