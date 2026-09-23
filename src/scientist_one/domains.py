"""Provider-independent, deterministic domain-validity adapters.

The trusted kernel owns provenance, state, custody, and gate authority.  This
module owns only domain-specific scientific predicates.  Adapters consume
immutable typed evidence and return immutable outcomes; they never mutate
research state, call providers, or confer evaluator/human authority.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import hmac
import math
import os
import re
import stat
from statistics import fmean, pstdev
from types import MappingProxyType
from typing import Callable, ClassVar, Iterable, Mapping, Protocol, runtime_checkable

from .artifacts import (
    MAX_REGISTRY_RECORDS,
    ArtifactRecord,
    ArtifactRegistry,
    RegistryValidationResult,
)
from .errors import (
    ArtifactError,
    LedgerError,
    UnsafeSerializationError,
    ValidationError,
)
from .ledger import (
    MAX_LEDGER_BYTES,
    MAX_LEDGER_EVENTS,
    EventLedger,
    LedgerEvent,
    LedgerValidationResult,
)
from .models import thaw_json, utc_now, validate_identifier
from .roles import Role
from .security import (
    canonical_json_bytes,
    open_confined_directory_fd,
    safe_json_loads,
    sha256_bytes,
)
from .generic_ml_projection import (
    GENERIC_ML_ATTESTATION_DOMAIN_SEPARATOR,
    GENERIC_ML_ATTESTATION_SCHEMA,
    GENERIC_ML_COMPARISON_SCOPE,
    GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
    GENERIC_ML_POLICY_SCHEMA,
    GENERIC_ML_VERIFIER_ID,
    GenericMLReferenceWork,
    GenericMLReferenceWorkPolicy,
    derive_generic_ml_projection_facts,
)


MAX_DOMAIN_RECORDS = 10_000
MAX_DOMAIN_TEXT_BYTES = 512
MAX_DOMAIN_CHECKS = 128
DOMAIN_RAW_FIXTURE_SCHEMA_VERSION = "domain-raw-fixture/v1"
DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION = "domain-evidence-source/v1"
DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION = "domain-evidence-manifest/v1"
DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION = "domain-validity-receipt/v1"
SCIENTIFIC_DOMAIN_EVIDENCE_PLAN_SCHEMA_VERSION = (
    "scientific-domain-evidence-plan/v1"
)
SCIENTIFIC_DOMAIN_EVIDENCE_PLAN_ARTIFACT_SCHEMA_VERSION = "domain-evidence-plan/v1"
SCIENTIFIC_DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION = "domain-evidence-source/v2"
SCIENTIFIC_DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION = "domain-evidence-manifest/v2"
SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION = "domain-validity-receipt/v2"
SCIENTIFIC_DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION_V3 = (
    "domain-evidence-manifest/v3"
)
SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION_V3 = (
    "domain-validity-receipt/v3"
)
SCIENTIFIC_DOMAIN_RAW_SOURCE_SCHEMA_VERSION = "scientific-domain-raw-source/v1"
_MACHINE_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RAW_SOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


class DomainInputError(ValidationError):
    """Typed domain evidence is malformed rather than merely unavailable."""


class ScientificDomainAdmissionUnavailable(DomainInputError):
    """A production domain source cannot currently be source-verified."""

    def __init__(
        self,
        status: "ScientificDomainAdmissionStatus",
        reason_code: str,
        reason: str,
    ) -> None:
        if not isinstance(status, ScientificDomainAdmissionStatus):
            raise DomainInputError("scientific domain admission status must be typed")
        _validate_text(reason_code, "scientific domain admission reason code")
        _validate_text(reason, "scientific domain admission reason")
        self.status = status
        self.reason_code = reason_code
        self.reason = reason
        super().__init__(reason)


class DomainKind(StrEnum):
    GENERIC_ML = "GENERIC_ML"
    MEDICAL_IMAGING = "MEDICAL_IMAGING"
    TIME_SERIES = "TIME_SERIES"
    RECOMMENDER_SYSTEMS = "RECOMMENDER_SYSTEMS"
    OPERATIONS_RESEARCH = "OPERATIONS_RESEARCH"
    SYSTEMS = "SYSTEMS"


class DomainValidityStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"


class DomainEvidenceScope(StrEnum):
    """Whether replayed domain inputs may be used as scientific evidence."""

    NON_EVIDENTIARY_FIXTURE = "NON_EVIDENTIARY_FIXTURE"
    SCIENTIFIC_EVIDENCE = "SCIENTIFIC_EVIDENCE"


class ScientificDomainAdmissionStatus(StrEnum):
    """Availability of one closed production raw-source verifier."""

    VERIFIED = "VERIFIED"
    BLOCKED_EXTERNAL = "BLOCKED_EXTERNAL"
    BLOCKED_LOCAL = "BLOCKED_LOCAL"
    UNSUPPORTED = "UNSUPPORTED"


class DomainValidityLimitation(StrEnum):
    """Closed limitations derived by the resolver rather than caller prose."""

    NON_EVIDENTIARY_FIXTURE = "NON_EVIDENTIARY_FIXTURE"
    REAL_WORKLOAD_UNTESTED = "REAL_WORKLOAD_UNTESTED"
    SCIENTIFIC_PROMOTION_PROHIBITED = "SCIENTIFIC_PROMOTION_PROHIBITED"
    EXTERNAL_VALIDATION_UNTESTED = "EXTERNAL_VALIDATION_UNTESTED"
    CLINICAL_VALIDATION_UNTESTED = "CLINICAL_VALIDATION_UNTESTED"


class SplitRole(StrEnum):
    TRAIN = "TRAIN"
    VALIDATION = "VALIDATION"
    TEST = "TEST"
    HOLDOUT = "HOLDOUT"


class MLPolicyTiming(StrEnum):
    FROZEN_BEFORE_RESULTS = "FROZEN_BEFORE_RESULTS"
    FROZEN_AFTER_RESULTS = "FROZEN_AFTER_RESULTS"
    UNVERIFIED = "UNVERIFIED"


class AugmentationMode(StrEnum):
    NONE = "NONE"
    TRAINING_ONLY = "TRAINING_ONLY"


class ComparisonDisposition(StrEnum):
    COMPARABLE = "COMPARABLE"
    JUSTIFIED_DIFFERENCE = "JUSTIFIED_DIFFERENCE"
    UNFAIR = "UNFAIR"
    UNAVAILABLE = "UNAVAILABLE"


class PretrainedContaminationStatus(StrEnum):
    CLEAR = "CLEAR"
    DETECTED = "DETECTED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class MedicalTask(StrEnum):
    CLASSIFICATION = "CLASSIFICATION"
    SEGMENTATION = "SEGMENTATION"
    REGISTRATION = "REGISTRATION"


class MedicalAnalysisUnit(StrEnum):
    PATIENT = "PATIENT"
    SUBJECT = "SUBJECT"
    SESSION = "SESSION"
    SCAN = "SCAN"
    VOLUME = "VOLUME"
    SLICE = "SLICE"


class MedicalImageRepresentation(StrEnum):
    IMAGE_2D = "IMAGE_2D"
    VOLUME_3D = "VOLUME_3D"


class MedicalClassificationTarget(StrEnum):
    BINARY = "BINARY"
    MULTICLASS = "MULTICLASS"
    MULTILABEL = "MULTILABEL"


class MedicalSegmentationTarget(StrEnum):
    BINARY_MASK = "BINARY_MASK"
    MULTICLASS_MASK = "MULTICLASS_MASK"
    INSTANCE_MASK = "INSTANCE_MASK"


class MedicalRegistrationTransform(StrEnum):
    RIGID_2D = "RIGID_2D"
    AFFINE_2D = "AFFINE_2D"
    DEFORMABLE_2D = "DEFORMABLE_2D"
    RIGID_3D = "RIGID_3D"
    AFFINE_3D = "AFFINE_3D"
    DEFORMABLE_3D = "DEFORMABLE_3D"


class MedicalRegistrationReference(StrEnum):
    LANDMARKS = "LANDMARKS"
    ANATOMICAL_LABELS = "ANATOMICAL_LABELS"
    DEFORMATION_FIELD = "DEFORMATION_FIELD"


class MedicalMetric(StrEnum):
    CLASSIFICATION_AUROC = "CLASSIFICATION_AUROC"
    CLASSIFICATION_AUPRC = "CLASSIFICATION_AUPRC"
    CLASSIFICATION_ACCURACY = "CLASSIFICATION_ACCURACY"
    CLASSIFICATION_SENSITIVITY = "CLASSIFICATION_SENSITIVITY"
    CLASSIFICATION_SPECIFICITY = "CLASSIFICATION_SPECIFICITY"
    CLASSIFICATION_BALANCED_ACCURACY = "CLASSIFICATION_BALANCED_ACCURACY"
    SEGMENTATION_DICE = "SEGMENTATION_DICE"
    SEGMENTATION_IOU = "SEGMENTATION_IOU"
    SEGMENTATION_HAUSDORFF_95_MM = "SEGMENTATION_HAUSDORFF_95_MM"
    SEGMENTATION_SURFACE_DICE = "SEGMENTATION_SURFACE_DICE"
    REGISTRATION_TARGET_REGISTRATION_ERROR_MM = (
        "REGISTRATION_TARGET_REGISTRATION_ERROR_MM"
    )
    REGISTRATION_LANDMARK_ERROR_MM = "REGISTRATION_LANDMARK_ERROR_MM"
    REGISTRATION_DICE_OVERLAP = "REGISTRATION_DICE_OVERLAP"
    REGISTRATION_JACOBIAN_FOLDING_RATE = (
        "REGISTRATION_JACOBIAN_FOLDING_RATE"
    )


class MedicalClinicalUse(StrEnum):
    SCREENING = "SCREENING"
    DIAGNOSTIC_SUPPORT = "DIAGNOSTIC_SUPPORT"
    PROGNOSTIC_STRATIFICATION = "PROGNOSTIC_STRATIFICATION"
    TREATMENT_PLANNING = "TREATMENT_PLANNING"
    PROCEDURAL_GUIDANCE = "PROCEDURAL_GUIDANCE"
    LONGITUDINAL_MONITORING = "LONGITUDINAL_MONITORING"


class MedicalThresholdBasis(StrEnum):
    MODEL_SCORE = "MODEL_SCORE"
    PRIMARY_METRIC = "PRIMARY_METRIC"


class MedicalThresholdUnit(StrEnum):
    PROBABILITY = "PROBABILITY"
    FRACTION = "FRACTION"
    MILLIMETERS = "MILLIMETERS"


class MedicalThresholdRelation(StrEnum):
    AT_LEAST = "AT_LEAST"
    AT_MOST = "AT_MOST"


class RecommenderSplitStrategy(StrEnum):
    TEMPORAL = "TEMPORAL"
    USER_DISJOINT = "USER_DISJOINT"
    ITEM_DISJOINT = "ITEM_DISJOINT"
    SESSION_DISJOINT = "SESSION_DISJOINT"


class ObjectiveDirection(StrEnum):
    MINIMIZE = "MINIMIZE"
    MAXIMIZE = "MAXIMIZE"


class MetricDirection(StrEnum):
    LOWER_IS_BETTER = "LOWER_IS_BETTER"
    HIGHER_IS_BETTER = "HIGHER_IS_BETTER"


class MetricScope(StrEnum):
    PROXY = "PROXY"
    END_TO_END = "END_TO_END"


class SystemsClaimScope(StrEnum):
    PROXY_ONLY = "PROXY_ONLY"
    SYSTEM_LEVEL = "SYSTEM_LEVEL"


def _validate_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DomainInputError(f"{label} must be non-empty text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DomainInputError(f"{label} must be valid UTF-8") from exc
    if len(encoded) > MAX_DOMAIN_TEXT_BYTES:
        raise DomainInputError(f"{label} exceeds the domain text limit")


def _validate_optional_text(value: str | None, label: str) -> None:
    if value is not None:
        _validate_text(value, label)


def _validate_sha256(value: str, label: str) -> None:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise DomainInputError(f"{label} must be a lowercase SHA-256 digest")


def _validate_optional_sha256(value: str | None, label: str) -> None:
    if value is not None:
        _validate_sha256(value, label)


def _validate_bool_or_none(value: bool | None, label: str) -> None:
    if value is not None and not isinstance(value, bool):
        raise DomainInputError(f"{label} must be boolean or unavailable")


def _validate_count(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DomainInputError(f"{label} must be a non-negative integer")


def _validate_finite(value: float | int | None, label: str) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DomainInputError(f"{label} must be finite numeric evidence")
    if not math.isfinite(float(value)):
        raise DomainInputError(f"{label} must be finite numeric evidence")


def _validate_records(values: tuple[object, ...], expected: type, label: str) -> None:
    if (
        not isinstance(values, tuple)
        or len(values) > MAX_DOMAIN_RECORDS
        or any(not isinstance(value, expected) for value in values)
    ):
        raise DomainInputError(f"{label} must be a bounded typed tuple")


def _validate_text_tuple(values: tuple[str, ...], label: str) -> None:
    if (
        not isinstance(values, tuple)
        or len(values) > MAX_DOMAIN_RECORDS
        or any(not isinstance(value, str) or not value.strip() for value in values)
    ):
        raise DomainInputError(f"{label} must be a bounded text tuple")
    for value in values:
        _validate_text(value, label)


def _validate_float_tuple(values: tuple[float, ...], label: str) -> None:
    if not isinstance(values, tuple) or len(values) > MAX_DOMAIN_RECORDS:
        raise DomainInputError(f"{label} must be a bounded numeric tuple")
    for value in values:
        _validate_finite(value, label)


@dataclass(frozen=True, slots=True)
class DomainCheck:
    """One deterministic domain predicate and the evidence needed to assess it."""

    machine_code: str
    status: DomainValidityStatus
    message: str
    evidence_requirements: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.machine_code, str) or not _MACHINE_CODE_RE.fullmatch(
            self.machine_code
        ):
            raise DomainInputError("domain machine code is invalid")
        if not isinstance(self.status, DomainValidityStatus):
            raise DomainInputError("domain check status must be typed")
        _validate_text(self.message, "domain check message")
        _validate_text_tuple(self.evidence_requirements, "evidence requirements")
        if not self.evidence_requirements:
            raise DomainInputError("domain checks must name required evidence")

    def to_dict(self) -> dict[str, object]:
        return {
            "machine_code": self.machine_code,
            "status": self.status.value,
            "message": self.message,
            "evidence_requirements": list(self.evidence_requirements),
        }


@dataclass(frozen=True, slots=True)
class DomainValidityOutcome:
    """Aggregate domain decision; FAIL outranks BLOCKED, which outranks PASS."""

    domain: DomainKind
    adapter_version: str
    status: DomainValidityStatus
    checks: tuple[DomainCheck, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.domain, DomainKind):
            raise DomainInputError("domain outcome kind must be typed")
        _validate_text(self.adapter_version, "adapter version")
        if (
            not isinstance(self.checks, tuple)
            or not self.checks
            or len(self.checks) > MAX_DOMAIN_CHECKS
            or any(not isinstance(check, DomainCheck) for check in self.checks)
        ):
            raise DomainInputError("domain outcome checks must be a bounded typed tuple")
        codes = tuple(check.machine_code for check in self.checks)
        if len(set(codes)) != len(codes):
            raise DomainInputError("domain outcome machine codes must be unique")
        expected = _aggregate_status(self.checks)
        if self.status is not expected:
            raise DomainInputError("domain outcome status disagrees with its checks")

    @property
    def machine_codes(self) -> tuple[str, ...]:
        codes = tuple(
            check.machine_code
            for check in self.checks
            if check.status is not DomainValidityStatus.PASS
        )
        return codes or (f"{self.domain.value}_VALIDITY_PASS",)

    @property
    def evidence_requirements(self) -> tuple[str, ...]:
        return _ordered_unique(
            requirement
            for check in self.checks
            for requirement in check.evidence_requirements
        )

    @property
    def unresolved_evidence_requirements(self) -> tuple[str, ...]:
        return _ordered_unique(
            requirement
            for check in self.checks
            if check.status is not DomainValidityStatus.PASS
            for requirement in check.evidence_requirements
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "domain": self.domain.value,
            "adapter_version": self.adapter_version,
            "status": self.status.value,
            "machine_codes": list(self.machine_codes),
            "evidence_requirements": list(self.evidence_requirements),
            "unresolved_evidence_requirements": list(
                self.unresolved_evidence_requirements
            ),
            "checks": [check.to_dict() for check in self.checks],
        }


@runtime_checkable
class DomainAdapter(Protocol):
    """Provider-neutral boundary for domain-owned scientific validity."""

    domain: DomainKind
    version: str

    def evaluate(self, evidence: object) -> DomainValidityOutcome:
        """Return a deterministic typed outcome without mutating kernel state."""


def _ordered_unique(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return tuple(result)


def _aggregate_status(checks: tuple[DomainCheck, ...]) -> DomainValidityStatus:
    if any(check.status is DomainValidityStatus.FAIL for check in checks):
        return DomainValidityStatus.FAIL
    if any(check.status is DomainValidityStatus.BLOCKED for check in checks):
        return DomainValidityStatus.BLOCKED
    return DomainValidityStatus.PASS


def _result(
    domain: DomainKind, version: str, checks: list[DomainCheck]
) -> DomainValidityOutcome:
    frozen_checks = tuple(checks)
    return DomainValidityOutcome(
        domain=domain,
        adapter_version=version,
        status=_aggregate_status(frozen_checks),
        checks=frozen_checks,
    )


def _check(
    code: str,
    status: DomainValidityStatus,
    message: str,
    *requirements: str,
) -> DomainCheck:
    return DomainCheck(code, status, message, tuple(requirements))


def _documented(
    value: bool | None,
    code: str,
    description: str,
    *requirements: str,
) -> DomainCheck:
    if value is True:
        return _check(code, DomainValidityStatus.PASS, description, *requirements)
    return _check(
        code,
        DomainValidityStatus.BLOCKED,
        f"Required evidence is unavailable: {description}",
        *requirements,
    )


def _input_mismatch(
    domain: DomainKind, version: str, expected: type
) -> DomainValidityOutcome:
    return _result(
        domain,
        version,
        [
            _check(
                f"{domain.value}_INPUT_TYPE_MISMATCH",
                DomainValidityStatus.BLOCKED,
                f"Adapter requires immutable {expected.__name__} evidence.",
                f"typed:{expected.__name__}",
            )
        ],
    )


def _cross_split(values: tuple[object, ...], attribute: str) -> bool:
    roles: dict[str, set[SplitRole]] = {}
    for value in values:
        identifier = getattr(value, attribute)
        if identifier is not None:
            roles.setdefault(identifier, set()).add(getattr(value, "split"))
    return any(len(items) > 1 for items in roles.values())


def _duplicates_across_splits(values: tuple[object, ...], attribute: str) -> bool:
    return _cross_split(values, attribute)


# ---------------------------------------------------------------------------
# Generic ML


@dataclass(frozen=True, slots=True)
class GenericMLExample:
    example_id: str
    split: SplitRole

    def __post_init__(self) -> None:
        _validate_text(self.example_id, "example ID")
        if not isinstance(self.split, SplitRole):
            raise DomainInputError("example split must be typed")


@dataclass(frozen=True, slots=True)
class EarlyStoppingPolicyEvidence:
    enabled: bool
    monitor_split: SplitRole | None
    policy_artifact_sha256: str
    timing: MLPolicyTiming

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise DomainInputError("early-stopping enabled flag must be boolean")
        if self.monitor_split is not None and not isinstance(
            self.monitor_split, SplitRole
        ):
            raise DomainInputError("early-stopping monitor split must be typed")
        if not self.enabled and self.monitor_split is not None:
            raise DomainInputError(
                "disabled early stopping cannot name a monitor split"
            )
        _validate_sha256(
            self.policy_artifact_sha256, "early-stopping policy artifact"
        )
        if not isinstance(self.timing, MLPolicyTiming):
            raise DomainInputError("early-stopping policy timing must be typed")


@dataclass(frozen=True, slots=True)
class AugmentationPolicyEvidence:
    mode: AugmentationMode
    fit_splits: tuple[SplitRole, ...]
    application_splits: tuple[SplitRole, ...]
    policy_artifact_sha256: str
    timing: MLPolicyTiming

    def __post_init__(self) -> None:
        if not isinstance(self.mode, AugmentationMode):
            raise DomainInputError("augmentation mode must be typed")
        for values, label in (
            (self.fit_splits, "augmentation fit splits"),
            (self.application_splits, "augmentation application splits"),
        ):
            if (
                not isinstance(values, tuple)
                or len(values) > len(SplitRole)
                or any(not isinstance(role, SplitRole) for role in values)
                or len(values) != len(set(values))
            ):
                raise DomainInputError(f"{label} must be a unique typed tuple")
        _validate_sha256(
            self.policy_artifact_sha256, "augmentation policy artifact"
        )
        if not isinstance(self.timing, MLPolicyTiming):
            raise DomainInputError("augmentation policy timing must be typed")


@dataclass(frozen=True, slots=True)
class ModelResourceComparisonEvidence:
    candidate_parameter_count: int
    baseline_parameter_count: int
    candidate_resource_profile_sha256: str
    baseline_resource_profile_sha256: str
    parameter_count_disposition: ComparisonDisposition
    resource_disposition: ComparisonDisposition
    comparison_artifact_sha256: str | None
    justification_artifact_sha256: str | None = None

    def __post_init__(self) -> None:
        _validate_count(self.candidate_parameter_count, "candidate parameter count")
        _validate_count(self.baseline_parameter_count, "baseline parameter count")
        _validate_sha256(
            self.candidate_resource_profile_sha256, "candidate resource profile"
        )
        _validate_sha256(
            self.baseline_resource_profile_sha256, "baseline resource profile"
        )
        for value, label in (
            (self.parameter_count_disposition, "parameter-count disposition"),
            (self.resource_disposition, "resource disposition"),
        ):
            if not isinstance(value, ComparisonDisposition):
                raise DomainInputError(f"{label} must be typed")
        _validate_optional_sha256(
            self.comparison_artifact_sha256, "resource comparison artifact"
        )
        _validate_optional_sha256(
            self.justification_artifact_sha256, "resource justification artifact"
        )


@dataclass(frozen=True, slots=True)
class PretrainedResourceEvidence:
    resource_id: str
    version: str
    artifact_sha256: str
    training_data_manifest_sha256: str | None

    def __post_init__(self) -> None:
        _validate_text(self.resource_id, "pretrained resource ID")
        _validate_text(self.version, "pretrained resource version")
        _validate_sha256(self.artifact_sha256, "pretrained resource artifact")
        _validate_optional_sha256(
            self.training_data_manifest_sha256,
            "pretrained resource training-data manifest",
        )


@dataclass(frozen=True, slots=True)
class PretrainedResourcePolicyEvidence:
    resources: tuple[PretrainedResourceEvidence, ...]
    inventory_artifact_sha256: str
    contamination_status: PretrainedContaminationStatus
    contamination_assessment_artifact_sha256: str | None

    def __post_init__(self) -> None:
        _validate_records(
            self.resources, PretrainedResourceEvidence, "pretrained resources"
        )
        identities = tuple(
            (resource.resource_id, resource.version) for resource in self.resources
        )
        if len(identities) != len(set(identities)):
            raise DomainInputError("pretrained resource identities must be unique")
        _validate_sha256(
            self.inventory_artifact_sha256, "pretrained resource inventory"
        )
        if not isinstance(
            self.contamination_status, PretrainedContaminationStatus
        ):
            raise DomainInputError("pretrained contamination status must be typed")
        _validate_optional_sha256(
            self.contamination_assessment_artifact_sha256,
            "pretrained contamination assessment artifact",
        )


@dataclass(frozen=True, slots=True)
class GenericMLValidityEvidence:
    examples: tuple[GenericMLExample, ...]
    preprocessing_fit_splits: tuple[SplitRole, ...]
    benchmark_version: str | None
    pretrained_contamination_checked: bool | None
    seed_policy_frozen: bool | None
    checkpoint_selection_split: SplitRole | None
    metric_implementation_verified: bool | None
    hyperparameter_budget_equivalent: bool | None
    compute_budget_equivalent: bool | None
    robustness_evaluated: bool | None
    generalization_claimed: bool = False
    external_validation_performed: bool | None = None
    early_stopping_policy: EarlyStoppingPolicyEvidence | None = None
    augmentation_policy: AugmentationPolicyEvidence | None = None
    model_resource_comparison: ModelResourceComparisonEvidence | None = None
    pretrained_resource_policy: PretrainedResourcePolicyEvidence | None = None

    def __post_init__(self) -> None:
        _validate_records(self.examples, GenericMLExample, "ML examples")
        if not self.examples:
            raise DomainInputError("ML evidence must contain examples")
        if not isinstance(self.preprocessing_fit_splits, tuple) or any(
            not isinstance(role, SplitRole) for role in self.preprocessing_fit_splits
        ):
            raise DomainInputError("preprocessing splits must be a typed tuple")
        _validate_optional_text(self.benchmark_version, "benchmark version")
        for name in (
            "pretrained_contamination_checked",
            "seed_policy_frozen",
            "metric_implementation_verified",
            "hyperparameter_budget_equivalent",
            "compute_budget_equivalent",
            "robustness_evaluated",
            "external_validation_performed",
        ):
            _validate_bool_or_none(getattr(self, name), name)
        if self.checkpoint_selection_split is not None and not isinstance(
            self.checkpoint_selection_split, SplitRole
        ):
            raise DomainInputError("checkpoint selection split must be typed")
        if not isinstance(self.generalization_claimed, bool):
            raise DomainInputError("generalization claim flag must be boolean")
        for value, expected, label in (
            (
                self.early_stopping_policy,
                EarlyStoppingPolicyEvidence,
                "early-stopping policy evidence",
            ),
            (
                self.augmentation_policy,
                AugmentationPolicyEvidence,
                "augmentation policy evidence",
            ),
            (
                self.model_resource_comparison,
                ModelResourceComparisonEvidence,
                "model resource comparison evidence",
            ),
            (
                self.pretrained_resource_policy,
                PretrainedResourcePolicyEvidence,
                "pretrained resource policy evidence",
            ),
        ):
            if value is not None and not isinstance(value, expected):
                raise DomainInputError(f"{label} must be typed or unavailable")


def _fixed_model_domain_native_copy(value: object) -> object:
    """Revalidate this closed inert profile before equality or arithmetic.

    Legacy constructors intentionally retain their historical permissiveness.
    The new profile first excludes scalar/container/record subclasses, then
    reconstructs each exact nested record, including mutated frozen values.
    This is shape validation, never scientific source authentication.
    """

    # At most 10,000 examples (record + two leaves each), plus fixed fields.
    # Bound the whole traversal, not just each tuple: mutated records can
    # otherwise hide an exponentially repeated tuple tree before validation.
    remaining_nodes = 3 * MAX_DOMAIN_RECORDS + 256

    def copy(current: object, depth: int) -> object:
        nonlocal remaining_nodes
        remaining_nodes -= 1
        if remaining_nodes < 0:
            raise DomainInputError("fixed-model evidence exceeds its total node budget")
        if depth > 8:
            raise DomainInputError("fixed-model evidence nesting is invalid")
        value_type = type(current)
        if value_type is str:
            if len(current) > MAX_DOMAIN_TEXT_BYTES:
                raise DomainInputError("fixed-model text exceeds its bound")
            return current
        if any(value_type is allowed for allowed in (int, bool, type(None))):
            return current
        if value_type is float:
            if not math.isfinite(current):
                raise DomainInputError("fixed-model numeric evidence must be finite")
            return current
        if any(value_type is allowed for allowed in (
            SplitRole, MLPolicyTiming, AugmentationMode, ComparisonDisposition,
            PretrainedContaminationStatus,
        )):
            return current
        if value_type is tuple:
            if len(current) > MAX_DOMAIN_RECORDS:
                raise DomainInputError("fixed-model evidence tuple exceeds its bound")
            return tuple(copy(item, depth + 1) for item in current)
        if any(value_type is allowed for allowed in (
            GenericMLExample, EarlyStoppingPolicyEvidence, AugmentationPolicyEvidence,
            ModelResourceComparisonEvidence, PretrainedResourceEvidence,
            PretrainedResourcePolicyEvidence, GenericMLValidityEvidence,
            GenericMLReferenceWorkPolicy, GenericMLReferenceWork,
        )):
            values = {
                item.name: copy(getattr(current, item.name), depth + 1)
                for item in fields(current)
            }
            try:
                return value_type(**values)
            except (TypeError, ValueError, ValidationError) as exc:
                raise DomainInputError("fixed-model nested evidence is invalid") from exc
        raise DomainInputError("fixed-model evidence requires exact native values")

    return copy(value, 0)


@dataclass(frozen=True, slots=True)
class GenericMLFixedModelValidityEvidence:
    """Inert fixed-model facts, not execution or scientific admission authority.

    The activity flag means only that the recorded actions contain no selection
    trial, adaptive branch, evaluator query, or confirmatory-label access. It
    proves neither a complete production sequence nor absence of all training.
    Full grid replay and execution admissibility remain separate obligations.
    Reference work concerns primary dense integer-linear inference only; the
    candidate's two robustness repetitions are separate overhead. Declared
    run-wide limits do not measure actual or per-condition resource use.
    """

    legacy_evidence: GenericMLValidityEvidence
    reference_work_policy: GenericMLReferenceWorkPolicy
    reference_work: GenericMLReferenceWork
    statistical_use_authority_artifact_sha256: str
    statistical_use_authority_record_hash: str
    no_recorded_selection_or_protected_label_access: bool
    requested_timeout_seconds: float
    contract_wall_cap_seconds: float

    def __post_init__(self) -> None:
        for name, expected in (
            ("legacy_evidence", GenericMLValidityEvidence),
            ("reference_work_policy", GenericMLReferenceWorkPolicy),
            ("reference_work", GenericMLReferenceWork),
        ):
            value = getattr(self, name)
            if type(value) is not expected:
                raise DomainInputError(f"fixed-model {name} must have its exact type")
            object.__setattr__(self, name, _fixed_model_domain_native_copy(value))
        for name in (
            "statistical_use_authority_artifact_sha256",
            "statistical_use_authority_record_hash",
        ):
            value = getattr(self, name)
            if type(value) is not str:
                raise DomainInputError(f"fixed-model {name} requires native text")
            _validate_sha256(value, name)
        if type(self.no_recorded_selection_or_protected_label_access) is not bool:
            raise DomainInputError("fixed-model recorded-action predicate must be boolean")
        for name in ("requested_timeout_seconds", "contract_wall_cap_seconds"):
            value = getattr(self, name)
            if type(value) is not int and type(value) is not float:
                raise DomainInputError(f"fixed-model {name} requires a native number")
            try:
                number = float(value)
            except (OverflowError, ValueError) as exc:
                raise DomainInputError(f"fixed-model {name} must be finite") from exc
            if not math.isfinite(number) or number <= 0:
                raise DomainInputError(f"fixed-model {name} must be positive and finite")
            # Keep the native value: converting two distinct large integers
            # to binary64 before the declared-cap comparison can erase excess.
        legacy = self.legacy_evidence
        if (
            legacy.preprocessing_fit_splits != ()
            or legacy.checkpoint_selection_split is not None
            or legacy.compute_budget_equivalent is not None
            or legacy.generalization_claimed is not False
            or legacy.external_validation_performed is not None
            or (legacy.early_stopping_policy is not None and (
                legacy.early_stopping_policy.enabled is not False
                or legacy.early_stopping_policy.monitor_split is not None
            ))
            or (legacy.augmentation_policy is not None and (
                legacy.augmentation_policy.mode is not AugmentationMode.NONE
                or legacy.augmentation_policy.fit_splits != ()
                or legacy.augmentation_policy.application_splits != ()
            ))
            or (legacy.pretrained_resource_policy is not None
                and legacy.pretrained_resource_policy.resources != ())
        ):
            raise DomainInputError("legacy evidence contradicts the closed fixed-model profile")
        comparison = legacy.model_resource_comparison
        if comparison is not None:
            expected_parameters = self.reference_work.class_count * (
                self.reference_work.feature_count + 1
            )
            if (
                comparison.resource_disposition is not ComparisonDisposition.UNAVAILABLE
                or comparison.candidate_parameter_count != expected_parameters
                or comparison.baseline_parameter_count != expected_parameters
            ):
                raise DomainInputError("fixed-model parameter or resource facts contradict reference work")


@dataclass(frozen=True, slots=True)
class GenericMLAdapter:
    domain: ClassVar[DomainKind] = DomainKind.GENERIC_ML
    version: ClassVar[str] = "2.0"

    def evaluate(self, evidence: object) -> DomainValidityOutcome:
        if not isinstance(evidence, GenericMLValidityEvidence):
            return _input_mismatch(self.domain, self.version, GenericMLValidityEvidence)
        checks: list[DomainCheck] = []
        checks.append(
            _check(
                "ML_EXAMPLE_SPLIT_LEAKAGE",
                DomainValidityStatus.FAIL
                if _duplicates_across_splits(evidence.examples, "example_id")
                else DomainValidityStatus.PASS,
                "Example identities must be disjoint across data splits.",
                "dataset.example_id",
                "dataset.split_assignment",
            )
        )
        preprocessing_leakage = any(
            role in {SplitRole.TEST, SplitRole.HOLDOUT}
            for role in evidence.preprocessing_fit_splits
        )
        checks.append(
            _check(
                "ML_PREPROCESSING_LEAKAGE",
                DomainValidityStatus.FAIL
                if preprocessing_leakage
                else DomainValidityStatus.PASS,
                "Preprocessing fitting must exclude test and holdout data.",
                "preprocessing.fit_split_manifest",
            )
        )
        checkpoint_invalid = evidence.checkpoint_selection_split in {
            SplitRole.TEST,
            SplitRole.HOLDOUT,
        }
        checkpoint_status = (
            DomainValidityStatus.BLOCKED
            if evidence.checkpoint_selection_split is None
            else DomainValidityStatus.FAIL
            if checkpoint_invalid
            else DomainValidityStatus.PASS
        )
        checks.append(
            _check(
                "ML_CHECKPOINT_SELECTION_LEAKAGE",
                checkpoint_status,
                "Checkpoint selection must use development evidence only.",
                "training.checkpoint_selection_policy",
            )
        )
        early_stopping = evidence.early_stopping_policy
        early_stopping_timing_status = (
            DomainValidityStatus.BLOCKED
            if early_stopping is None
            or early_stopping.timing is MLPolicyTiming.UNVERIFIED
            else DomainValidityStatus.FAIL
            if early_stopping.timing is MLPolicyTiming.FROZEN_AFTER_RESULTS
            else DomainValidityStatus.PASS
        )
        checks.append(
            _check(
                "ML_EARLY_STOPPING_POLICY_NOT_FROZEN",
                early_stopping_timing_status,
                "The early-stopping policy must be frozen before results.",
                "training.early_stopping_policy_artifact",
                "training.early_stopping_policy_timing",
            )
        )
        if early_stopping is None:
            early_stopping_split_status = DomainValidityStatus.BLOCKED
        elif not early_stopping.enabled:
            early_stopping_split_status = DomainValidityStatus.PASS
        elif early_stopping.monitor_split is None:
            early_stopping_split_status = DomainValidityStatus.BLOCKED
        elif early_stopping.monitor_split in {SplitRole.TEST, SplitRole.HOLDOUT}:
            early_stopping_split_status = DomainValidityStatus.FAIL
        else:
            early_stopping_split_status = DomainValidityStatus.PASS
        checks.append(
            _check(
                "ML_EARLY_STOPPING_SPLIT_LEAKAGE",
                early_stopping_split_status,
                "Early stopping must use a declared development split only.",
                "training.early_stopping_monitor_split",
                "training.early_stopping_policy_artifact",
            )
        )
        augmentation = evidence.augmentation_policy
        augmentation_timing_status = (
            DomainValidityStatus.BLOCKED
            if augmentation is None
            or augmentation.timing is MLPolicyTiming.UNVERIFIED
            else DomainValidityStatus.FAIL
            if augmentation.timing is MLPolicyTiming.FROZEN_AFTER_RESULTS
            else DomainValidityStatus.PASS
        )
        checks.append(
            _check(
                "ML_AUGMENTATION_POLICY_NOT_FROZEN",
                augmentation_timing_status,
                "The augmentation policy must be frozen before results.",
                "training.augmentation_policy_artifact",
                "training.augmentation_policy_timing",
            )
        )
        if augmentation is None:
            augmentation_fit_status = DomainValidityStatus.BLOCKED
        elif augmentation.mode is AugmentationMode.NONE:
            augmentation_fit_status = (
                DomainValidityStatus.FAIL
                if augmentation.fit_splits
                else DomainValidityStatus.PASS
            )
        else:
            augmentation_fit_status = (
                DomainValidityStatus.FAIL
                if any(
                    role in {SplitRole.TEST, SplitRole.HOLDOUT}
                    for role in augmentation.fit_splits
                )
                else DomainValidityStatus.PASS
            )
        checks.append(
            _check(
                "ML_AUGMENTATION_FIT_LEAKAGE",
                augmentation_fit_status,
                "Augmentation fitting must exclude test and holdout evidence.",
                "training.augmentation_fit_split_manifest",
                "training.augmentation_policy_artifact",
            )
        )
        if augmentation is None:
            augmentation_application_status = DomainValidityStatus.BLOCKED
        elif augmentation.mode is AugmentationMode.NONE:
            augmentation_application_status = (
                DomainValidityStatus.FAIL
                if augmentation.application_splits
                else DomainValidityStatus.PASS
            )
        elif not augmentation.application_splits:
            augmentation_application_status = DomainValidityStatus.BLOCKED
        else:
            augmentation_application_status = (
                DomainValidityStatus.PASS
                if set(augmentation.application_splits) == {SplitRole.TRAIN}
                else DomainValidityStatus.FAIL
            )
        checks.append(
            _check(
                "ML_AUGMENTATION_APPLICATION_POLICY_INVALID",
                augmentation_application_status,
                "Training augmentation must be applied only to the training split.",
                "training.augmentation_application_split_manifest",
                "training.augmentation_policy_artifact",
            )
        )
        checks.append(
            _check(
                "ML_BENCHMARK_VERSION_MISSING",
                DomainValidityStatus.PASS
                if evidence.benchmark_version
                else DomainValidityStatus.BLOCKED,
                "Benchmark identity and version must be frozen.",
                "dataset.benchmark_version",
            )
        )
        pretrained_policy = evidence.pretrained_resource_policy
        pretrained_identity_incomplete = (
            pretrained_policy is not None
            and any(
                resource.training_data_manifest_sha256 is None
                for resource in pretrained_policy.resources
            )
        )
        if pretrained_policy is None:
            pretrained_identity_status = DomainValidityStatus.BLOCKED
        elif pretrained_identity_incomplete:
            pretrained_identity_status = DomainValidityStatus.BLOCKED
        else:
            pretrained_identity_status = DomainValidityStatus.PASS
        checks.append(
            _check(
                "ML_PRETRAINED_RESOURCE_IDENTITY_MISSING",
                pretrained_identity_status,
                "Every pretrained resource and its training-data manifest must have a frozen identity.",
                "model.pretrained_resource_inventory",
                "model.pretrained_resource_artifacts",
                "model.pretraining_data_manifests",
            )
        )
        if pretrained_policy is None:
            pretrained_contamination_status = DomainValidityStatus.BLOCKED
        elif not pretrained_policy.resources:
            pretrained_contamination_status = (
                DomainValidityStatus.PASS
                if pretrained_policy.contamination_status
                is PretrainedContaminationStatus.NOT_APPLICABLE
                else DomainValidityStatus.FAIL
            )
        elif (
            pretrained_policy.contamination_status
            is PretrainedContaminationStatus.DETECTED
        ):
            pretrained_contamination_status = DomainValidityStatus.FAIL
        elif (
            pretrained_policy.contamination_status
            is PretrainedContaminationStatus.NOT_APPLICABLE
        ):
            pretrained_contamination_status = DomainValidityStatus.FAIL
        elif pretrained_identity_incomplete:
            pretrained_contamination_status = DomainValidityStatus.BLOCKED
        elif (
            pretrained_policy.contamination_status
            is PretrainedContaminationStatus.UNKNOWN
            or pretrained_policy.contamination_assessment_artifact_sha256 is None
        ):
            pretrained_contamination_status = DomainValidityStatus.BLOCKED
        elif evidence.pretrained_contamination_checked is False:
            pretrained_contamination_status = DomainValidityStatus.FAIL
        else:
            pretrained_contamination_status = DomainValidityStatus.PASS
        checks.append(
            _check(
                "ML_PRETRAINED_CONTAMINATION_UNCHECKED",
                pretrained_contamination_status,
                "Pretrained-resource contamination must be assessed against frozen identities.",
                "model.pretrained_resource_inventory",
                "model.pretraining_data_assessment",
            )
        )
        checks.extend(
            (
                _documented(
                    evidence.seed_policy_frozen,
                    "ML_SEED_POLICY_MISSING",
                    "Seed and selection policy was frozen.",
                    "protocol.seed_policy",
                ),
                _documented(
                    evidence.metric_implementation_verified,
                    "ML_METRIC_IMPLEMENTATION_UNVERIFIED",
                    "Metric implementation was verified against bound reference vectors.",
                    "evaluator.metric_verification",
                ),
            )
        )
        resource_comparison = evidence.model_resource_comparison

        def comparison_status(
            disposition: ComparisonDisposition | None,
        ) -> DomainValidityStatus:
            if resource_comparison is None or disposition is None:
                return DomainValidityStatus.BLOCKED
            if disposition is ComparisonDisposition.UNFAIR:
                return DomainValidityStatus.FAIL
            if disposition is ComparisonDisposition.UNAVAILABLE:
                return DomainValidityStatus.BLOCKED
            if resource_comparison.comparison_artifact_sha256 is None:
                return DomainValidityStatus.BLOCKED
            if (
                disposition is ComparisonDisposition.JUSTIFIED_DIFFERENCE
                and resource_comparison.justification_artifact_sha256 is None
            ):
                return DomainValidityStatus.BLOCKED
            return DomainValidityStatus.PASS

        checks.append(
            _check(
                "ML_PARAMETER_COUNT_COMPARABILITY",
                comparison_status(
                    resource_comparison.parameter_count_disposition
                    if resource_comparison is not None
                    else None
                ),
                "Candidate and baseline parameter counts must be comparable or have an artifact-backed justification.",
                "baseline.candidate_parameter_count",
                "baseline.baseline_parameter_count",
                "baseline.resource_comparison_artifact",
                "baseline.resource_difference_justification",
            )
        )
        checks.append(
            _check(
                "ML_RESOURCE_COMPARABILITY",
                comparison_status(
                    resource_comparison.resource_disposition
                    if resource_comparison is not None
                    else None
                ),
                "Candidate and baseline resource profiles must be comparable or have an artifact-backed justification.",
                "baseline.candidate_resource_profile",
                "baseline.baseline_resource_profile",
                "baseline.resource_comparison_artifact",
                "baseline.resource_difference_justification",
            )
        )
        for flag, code, description, requirement in (
            (
                evidence.hyperparameter_budget_equivalent,
                "ML_HYPERPARAMETER_BUDGET_UNFAIR",
                "Candidate and baseline hyperparameter budgets are equivalent.",
                "baseline.hyperparameter_budget_comparison",
            ),
            (
                evidence.compute_budget_equivalent,
                "ML_COMPUTE_BUDGET_UNFAIR",
                "Candidate and baseline compute budgets are equivalent.",
                "baseline.compute_budget_comparison",
            ),
        ):
            status = (
                DomainValidityStatus.BLOCKED
                if flag is None
                else DomainValidityStatus.PASS
                if flag
                else DomainValidityStatus.FAIL
            )
            checks.append(_check(code, status, description, requirement))
        checks.append(
            _documented(
                evidence.robustness_evaluated,
                "ML_ROBUSTNESS_EVIDENCE_MISSING",
                "Required robustness evaluation was completed.",
                "evaluation.robustness_results",
            )
        )
        if evidence.generalization_claimed:
            status = (
                DomainValidityStatus.BLOCKED
                if evidence.external_validation_performed is None
                else DomainValidityStatus.PASS
                if evidence.external_validation_performed
                else DomainValidityStatus.FAIL
            )
            checks.append(
                _check(
                    "ML_GENERALIZATION_OVERCLAIM",
                    status,
                    "A generalization claim requires compatible external validation.",
                    "evaluation.external_validation",
                    "claim.generalization_scope",
                )
            )
        return _result(self.domain, self.version, checks)


@dataclass(frozen=True, slots=True)
class GenericMLFixedModelAdapter:
    """Pure scoped adapter; scientific admission still requires full source replay."""

    domain: ClassVar[DomainKind] = DomainKind.GENERIC_ML
    version: ClassVar[str] = "3.0"

    def evaluate(self, evidence: object) -> DomainValidityOutcome:
        if type(evidence) is not GenericMLFixedModelValidityEvidence:
            return _input_mismatch(self.domain, self.version, GenericMLFixedModelValidityEvidence)
        evidence = replace(evidence)
        legacy = GenericMLAdapter().evaluate(evidence.legacy_evidence)
        replacements = {
            "ML_CHECKPOINT_SELECTION_LEAKAGE": _check(
                "ML_FIXED_MODEL_NO_RECORDED_SELECTION",
                DomainValidityStatus.PASS
                if evidence.no_recorded_selection_or_protected_label_access
                else DomainValidityStatus.FAIL,
                "Recorded actions contain no selection trial, adaptive branch, evaluator query, "
                "or confirmatory-label access; this does not establish absence of training.",
                "execution.recorded_action_predicate",
            ),
            "ML_RESOURCE_COMPARABILITY": _check(
                "ML_FIXED_MODEL_PRIMARY_REFERENCE_WORK_EQUAL",
                DomainValidityStatus.PASS
                if evidence.legacy_evidence.model_resource_comparison is not None
                else DomainValidityStatus.BLOCKED,
                "Candidate and baseline have equal primary dense integer-linear reference work "
                "over N/S/C/F, not equal actual instructions, total work, time, memory, or energy; "
                "candidate robustness adds two separate repetitions.",
                "protocol.fixed_model_reference_work_policy",
                "baseline.primary_reference_work",
            ),
            "ML_COMPUTE_BUDGET_UNFAIR": _check(
                "ML_FIXED_MODEL_DECLARED_RUN_CAP",
                DomainValidityStatus.PASS
                if evidence.requested_timeout_seconds <= evidence.contract_wall_cap_seconds
                else DomainValidityStatus.FAIL,
                "The declared run timeout must not exceed the common contract run-wide wall cap; "
                "this is not observed or per-condition resource accounting.",
                "protocol.declared_run_timeout",
                "contract.run_wide_wall_cap",
            ),
        }
        if sum(check.machine_code in replacements for check in legacy.checks) != 3:
            raise DomainInputError("fixed-model adapter requires the exact three legacy obligations")
        return _result(self.domain, self.version, [
            replacements.get(check.machine_code, check) for check in legacy.checks
        ])


# ---------------------------------------------------------------------------
# Medical imaging


@dataclass(frozen=True, slots=True)
class MedicalImageObservation:
    image_id: str
    split: SplitRole
    patient_id: str | None
    subject_id: str | None
    session_id: str | None
    scan_id: str | None
    site_id: str | None

    def __post_init__(self) -> None:
        _validate_text(self.image_id, "image ID")
        if not isinstance(self.split, SplitRole):
            raise DomainInputError("medical split must be typed")
        for name in ("patient_id", "subject_id", "session_id", "scan_id", "site_id"):
            _validate_optional_text(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class MedicalClassificationSemantics:
    input_representation: MedicalImageRepresentation
    target: MedicalClassificationTarget
    primary_metric: MedicalMetric
    metric_direction: MetricDirection
    protocol_artifact_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.input_representation, MedicalImageRepresentation):
            raise DomainInputError(
                "classification input representation must be typed"
            )
        if not isinstance(self.target, MedicalClassificationTarget):
            raise DomainInputError("classification target must be typed")
        if not isinstance(self.primary_metric, MedicalMetric):
            raise DomainInputError("classification primary metric must be typed")
        if not isinstance(self.metric_direction, MetricDirection):
            raise DomainInputError("classification metric direction must be typed")
        _validate_sha256(
            self.protocol_artifact_sha256,
            "classification semantics protocol artifact",
        )


@dataclass(frozen=True, slots=True)
class MedicalSegmentationSemantics:
    image_representation: MedicalImageRepresentation
    mask_representation: MedicalImageRepresentation
    target: MedicalSegmentationTarget
    primary_metric: MedicalMetric
    metric_direction: MetricDirection
    protocol_artifact_sha256: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.image_representation, "segmentation image representation"),
            (self.mask_representation, "segmentation mask representation"),
        ):
            if not isinstance(value, MedicalImageRepresentation):
                raise DomainInputError(f"{label} must be typed")
        if not isinstance(self.target, MedicalSegmentationTarget):
            raise DomainInputError("segmentation target must be typed")
        if not isinstance(self.primary_metric, MedicalMetric):
            raise DomainInputError("segmentation primary metric must be typed")
        if not isinstance(self.metric_direction, MetricDirection):
            raise DomainInputError("segmentation metric direction must be typed")
        _validate_sha256(
            self.protocol_artifact_sha256,
            "segmentation semantics protocol artifact",
        )


@dataclass(frozen=True, slots=True)
class MedicalRegistrationSemantics:
    moving_representation: MedicalImageRepresentation
    fixed_representation: MedicalImageRepresentation
    transform: MedicalRegistrationTransform
    reference: MedicalRegistrationReference
    primary_metric: MedicalMetric
    metric_direction: MetricDirection
    protocol_artifact_sha256: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.moving_representation, "registration moving representation"),
            (self.fixed_representation, "registration fixed representation"),
        ):
            if not isinstance(value, MedicalImageRepresentation):
                raise DomainInputError(f"{label} must be typed")
        if not isinstance(self.transform, MedicalRegistrationTransform):
            raise DomainInputError("registration transform must be typed")
        if not isinstance(self.reference, MedicalRegistrationReference):
            raise DomainInputError("registration reference must be typed")
        if not isinstance(self.primary_metric, MedicalMetric):
            raise DomainInputError("registration primary metric must be typed")
        if not isinstance(self.metric_direction, MetricDirection):
            raise DomainInputError("registration metric direction must be typed")
        _validate_sha256(
            self.protocol_artifact_sha256,
            "registration semantics protocol artifact",
        )


MedicalTaskSemantics = (
    MedicalClassificationSemantics
    | MedicalSegmentationSemantics
    | MedicalRegistrationSemantics
)


@dataclass(frozen=True, slots=True)
class MedicalClinicalInterpretationEvidence:
    """Prespecified clinical context; structural validity is not clinical validation."""

    intended_use: MedicalClinicalUse
    target_population: str
    interpretation: str
    threshold_basis: MedicalThresholdBasis
    threshold_value: float
    threshold_unit: MedicalThresholdUnit
    threshold_relation: MedicalThresholdRelation
    context_artifact_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.intended_use, MedicalClinicalUse):
            raise DomainInputError("medical clinical use must be typed")
        _validate_text(self.target_population, "medical target population")
        _validate_text(self.interpretation, "medical clinical interpretation")
        if not isinstance(self.threshold_basis, MedicalThresholdBasis):
            raise DomainInputError("medical threshold basis must be typed")
        if self.threshold_value is None:
            raise DomainInputError("medical clinical threshold must be present")
        _validate_finite(self.threshold_value, "medical clinical threshold")
        if not isinstance(self.threshold_unit, MedicalThresholdUnit):
            raise DomainInputError("medical threshold unit must be typed")
        if not isinstance(self.threshold_relation, MedicalThresholdRelation):
            raise DomainInputError("medical threshold relation must be typed")
        _validate_sha256(
            self.context_artifact_sha256, "medical clinical-context artifact"
        )


@dataclass(frozen=True, slots=True)
class MedicalImagingValidityEvidence:
    observations: tuple[MedicalImageObservation, ...]
    task: MedicalTask
    analysis_unit: MedicalAnalysisUnit
    resampling_unit: MedicalAnalysisUnit
    site_disjoint_evaluation_required: bool
    modality_documented: bool | None
    acquisition_metadata_documented: bool | None
    preprocessing_frozen: bool | None
    calibration_evaluated: bool | None
    uncertainty_evaluated: bool | None
    subgroup_dimensions_evaluated: tuple[str, ...]
    required_subgroup_dimensions: tuple[str, ...]
    sensitive_data_controls_documented: bool | None
    external_validation_claimed: bool = False
    external_validation_performed: bool | None = None
    task_semantics: MedicalTaskSemantics | None = None
    clinical_interpretation: MedicalClinicalInterpretationEvidence | None = None

    def __post_init__(self) -> None:
        _validate_records(
            self.observations, MedicalImageObservation, "medical observations"
        )
        if not self.observations:
            raise DomainInputError("medical evidence must contain observations")
        if not isinstance(self.task, MedicalTask):
            raise DomainInputError("medical task must be typed")
        if not isinstance(self.analysis_unit, MedicalAnalysisUnit) or not isinstance(
            self.resampling_unit, MedicalAnalysisUnit
        ):
            raise DomainInputError("medical analysis units must be typed")
        if not isinstance(self.site_disjoint_evaluation_required, bool):
            raise DomainInputError("site split requirement must be boolean")
        for name in (
            "modality_documented",
            "acquisition_metadata_documented",
            "preprocessing_frozen",
            "calibration_evaluated",
            "uncertainty_evaluated",
            "sensitive_data_controls_documented",
            "external_validation_performed",
        ):
            _validate_bool_or_none(getattr(self, name), name)
        _validate_text_tuple(
            self.subgroup_dimensions_evaluated, "evaluated subgroup dimensions"
        )
        _validate_text_tuple(
            self.required_subgroup_dimensions, "required subgroup dimensions"
        )
        if not isinstance(self.external_validation_claimed, bool):
            raise DomainInputError("external validation claim flag must be boolean")
        if self.task_semantics is not None and not isinstance(
            self.task_semantics,
            (
                MedicalClassificationSemantics,
                MedicalSegmentationSemantics,
                MedicalRegistrationSemantics,
            ),
        ):
            raise DomainInputError(
                "medical task semantics must be typed or unavailable"
            )
        if self.clinical_interpretation is not None and not isinstance(
            self.clinical_interpretation, MedicalClinicalInterpretationEvidence
        ):
            raise DomainInputError(
                "medical clinical interpretation must be typed or unavailable"
            )


_MEDICAL_SEMANTICS_TYPES: dict[MedicalTask, type[MedicalTaskSemantics]] = {
    MedicalTask.CLASSIFICATION: MedicalClassificationSemantics,
    MedicalTask.SEGMENTATION: MedicalSegmentationSemantics,
    MedicalTask.REGISTRATION: MedicalRegistrationSemantics,
}

_MEDICAL_METRICS_BY_TASK: dict[MedicalTask, frozenset[MedicalMetric]] = {
    MedicalTask.CLASSIFICATION: frozenset(
        {
            MedicalMetric.CLASSIFICATION_AUROC,
            MedicalMetric.CLASSIFICATION_AUPRC,
            MedicalMetric.CLASSIFICATION_ACCURACY,
            MedicalMetric.CLASSIFICATION_SENSITIVITY,
            MedicalMetric.CLASSIFICATION_SPECIFICITY,
            MedicalMetric.CLASSIFICATION_BALANCED_ACCURACY,
        }
    ),
    MedicalTask.SEGMENTATION: frozenset(
        {
            MedicalMetric.SEGMENTATION_DICE,
            MedicalMetric.SEGMENTATION_IOU,
            MedicalMetric.SEGMENTATION_HAUSDORFF_95_MM,
            MedicalMetric.SEGMENTATION_SURFACE_DICE,
        }
    ),
    MedicalTask.REGISTRATION: frozenset(
        {
            MedicalMetric.REGISTRATION_TARGET_REGISTRATION_ERROR_MM,
            MedicalMetric.REGISTRATION_LANDMARK_ERROR_MM,
            MedicalMetric.REGISTRATION_DICE_OVERLAP,
            MedicalMetric.REGISTRATION_JACOBIAN_FOLDING_RATE,
        }
    ),
}

_MEDICAL_METRIC_DIRECTIONS: dict[MedicalMetric, MetricDirection] = {
    MedicalMetric.CLASSIFICATION_AUROC: MetricDirection.HIGHER_IS_BETTER,
    MedicalMetric.CLASSIFICATION_AUPRC: MetricDirection.HIGHER_IS_BETTER,
    MedicalMetric.CLASSIFICATION_ACCURACY: MetricDirection.HIGHER_IS_BETTER,
    MedicalMetric.CLASSIFICATION_SENSITIVITY: MetricDirection.HIGHER_IS_BETTER,
    MedicalMetric.CLASSIFICATION_SPECIFICITY: MetricDirection.HIGHER_IS_BETTER,
    MedicalMetric.CLASSIFICATION_BALANCED_ACCURACY: (
        MetricDirection.HIGHER_IS_BETTER
    ),
    MedicalMetric.SEGMENTATION_DICE: MetricDirection.HIGHER_IS_BETTER,
    MedicalMetric.SEGMENTATION_IOU: MetricDirection.HIGHER_IS_BETTER,
    MedicalMetric.SEGMENTATION_HAUSDORFF_95_MM: MetricDirection.LOWER_IS_BETTER,
    MedicalMetric.SEGMENTATION_SURFACE_DICE: MetricDirection.HIGHER_IS_BETTER,
    MedicalMetric.REGISTRATION_TARGET_REGISTRATION_ERROR_MM: (
        MetricDirection.LOWER_IS_BETTER
    ),
    MedicalMetric.REGISTRATION_LANDMARK_ERROR_MM: MetricDirection.LOWER_IS_BETTER,
    MedicalMetric.REGISTRATION_DICE_OVERLAP: MetricDirection.HIGHER_IS_BETTER,
    MedicalMetric.REGISTRATION_JACOBIAN_FOLDING_RATE: (
        MetricDirection.LOWER_IS_BETTER
    ),
}

_MEDICAL_METRIC_UNITS: dict[MedicalMetric, MedicalThresholdUnit] = {
    MedicalMetric.CLASSIFICATION_AUROC: MedicalThresholdUnit.FRACTION,
    MedicalMetric.CLASSIFICATION_AUPRC: MedicalThresholdUnit.FRACTION,
    MedicalMetric.CLASSIFICATION_ACCURACY: MedicalThresholdUnit.FRACTION,
    MedicalMetric.CLASSIFICATION_SENSITIVITY: MedicalThresholdUnit.FRACTION,
    MedicalMetric.CLASSIFICATION_SPECIFICITY: MedicalThresholdUnit.FRACTION,
    MedicalMetric.CLASSIFICATION_BALANCED_ACCURACY: MedicalThresholdUnit.FRACTION,
    MedicalMetric.SEGMENTATION_DICE: MedicalThresholdUnit.FRACTION,
    MedicalMetric.SEGMENTATION_IOU: MedicalThresholdUnit.FRACTION,
    MedicalMetric.SEGMENTATION_HAUSDORFF_95_MM: MedicalThresholdUnit.MILLIMETERS,
    MedicalMetric.SEGMENTATION_SURFACE_DICE: MedicalThresholdUnit.FRACTION,
    MedicalMetric.REGISTRATION_TARGET_REGISTRATION_ERROR_MM: (
        MedicalThresholdUnit.MILLIMETERS
    ),
    MedicalMetric.REGISTRATION_LANDMARK_ERROR_MM: (
        MedicalThresholdUnit.MILLIMETERS
    ),
    MedicalMetric.REGISTRATION_DICE_OVERLAP: MedicalThresholdUnit.FRACTION,
    MedicalMetric.REGISTRATION_JACOBIAN_FOLDING_RATE: MedicalThresholdUnit.FRACTION,
}

_MEDICAL_CLINICAL_USES: dict[MedicalTask, frozenset[MedicalClinicalUse]] = {
    MedicalTask.CLASSIFICATION: frozenset(
        {
            MedicalClinicalUse.SCREENING,
            MedicalClinicalUse.DIAGNOSTIC_SUPPORT,
            MedicalClinicalUse.PROGNOSTIC_STRATIFICATION,
        }
    ),
    MedicalTask.SEGMENTATION: frozenset(
        {
            MedicalClinicalUse.DIAGNOSTIC_SUPPORT,
            MedicalClinicalUse.TREATMENT_PLANNING,
            MedicalClinicalUse.PROCEDURAL_GUIDANCE,
            MedicalClinicalUse.LONGITUDINAL_MONITORING,
        }
    ),
    MedicalTask.REGISTRATION: frozenset(
        {
            MedicalClinicalUse.DIAGNOSTIC_SUPPORT,
            MedicalClinicalUse.TREATMENT_PLANNING,
            MedicalClinicalUse.PROCEDURAL_GUIDANCE,
            MedicalClinicalUse.LONGITUDINAL_MONITORING,
        }
    ),
}

_MEDICAL_TRANSFORM_REPRESENTATIONS: dict[
    MedicalRegistrationTransform, MedicalImageRepresentation
] = {
    MedicalRegistrationTransform.RIGID_2D: MedicalImageRepresentation.IMAGE_2D,
    MedicalRegistrationTransform.AFFINE_2D: MedicalImageRepresentation.IMAGE_2D,
    MedicalRegistrationTransform.DEFORMABLE_2D: (
        MedicalImageRepresentation.IMAGE_2D
    ),
    MedicalRegistrationTransform.RIGID_3D: MedicalImageRepresentation.VOLUME_3D,
    MedicalRegistrationTransform.AFFINE_3D: MedicalImageRepresentation.VOLUME_3D,
    MedicalRegistrationTransform.DEFORMABLE_3D: (
        MedicalImageRepresentation.VOLUME_3D
    ),
}

_MEDICAL_REGISTRATION_REFERENCES: dict[
    MedicalMetric, MedicalRegistrationReference
] = {
    MedicalMetric.REGISTRATION_TARGET_REGISTRATION_ERROR_MM: (
        MedicalRegistrationReference.LANDMARKS
    ),
    MedicalMetric.REGISTRATION_LANDMARK_ERROR_MM: (
        MedicalRegistrationReference.LANDMARKS
    ),
    MedicalMetric.REGISTRATION_DICE_OVERLAP: (
        MedicalRegistrationReference.ANATOMICAL_LABELS
    ),
    MedicalMetric.REGISTRATION_JACOBIAN_FOLDING_RATE: (
        MedicalRegistrationReference.DEFORMATION_FIELD
    ),
}


def _medical_primary_metric(semantics: MedicalTaskSemantics) -> MedicalMetric:
    return semantics.primary_metric


def _medical_metric_semantics_valid(
    task: MedicalTask, semantics: MedicalTaskSemantics
) -> bool:
    metric = _medical_primary_metric(semantics)
    if metric not in _MEDICAL_METRICS_BY_TASK[task]:
        return False
    if isinstance(semantics, MedicalRegistrationSemantics):
        if _MEDICAL_REGISTRATION_REFERENCES.get(metric) is not semantics.reference:
            return False
        if metric is MedicalMetric.REGISTRATION_JACOBIAN_FOLDING_RATE:
            return semantics.transform in {
                MedicalRegistrationTransform.DEFORMABLE_2D,
                MedicalRegistrationTransform.DEFORMABLE_3D,
            }
    return True


def _medical_representation_compatible(semantics: MedicalTaskSemantics) -> bool:
    if isinstance(semantics, MedicalClassificationSemantics):
        return True
    if isinstance(semantics, MedicalSegmentationSemantics):
        return semantics.image_representation is semantics.mask_representation
    return (
        semantics.moving_representation is semantics.fixed_representation
        and _MEDICAL_TRANSFORM_REPRESENTATIONS.get(semantics.transform)
        is semantics.moving_representation
    )


def _medical_threshold_valid(
    task: MedicalTask,
    semantics: MedicalTaskSemantics,
    context: MedicalClinicalInterpretationEvidence,
) -> bool:
    metric = _medical_primary_metric(semantics)
    if task is MedicalTask.CLASSIFICATION:
        expected_basis = MedicalThresholdBasis.MODEL_SCORE
        expected_unit = MedicalThresholdUnit.PROBABILITY
        expected_relation = MedicalThresholdRelation.AT_LEAST
    else:
        expected_basis = MedicalThresholdBasis.PRIMARY_METRIC
        expected_unit = _MEDICAL_METRIC_UNITS.get(metric)
        expected_direction = _MEDICAL_METRIC_DIRECTIONS.get(metric)
        if expected_unit is None or expected_direction is None:
            return False
        expected_relation = (
            MedicalThresholdRelation.AT_LEAST
            if expected_direction is MetricDirection.HIGHER_IS_BETTER
            else MedicalThresholdRelation.AT_MOST
        )
    threshold = float(context.threshold_value)
    in_range = (
        0.0 <= threshold <= 1.0
        if expected_unit
        in {MedicalThresholdUnit.PROBABILITY, MedicalThresholdUnit.FRACTION}
        else threshold >= 0.0
    )
    return (
        context.threshold_basis is expected_basis
        and context.threshold_unit is expected_unit
        and context.threshold_relation is expected_relation
        and in_range
    )


@dataclass(frozen=True, slots=True)
class MedicalImagingAdapter:
    domain: ClassVar[DomainKind] = DomainKind.MEDICAL_IMAGING
    version: ClassVar[str] = "2.0"

    def evaluate(self, evidence: object) -> DomainValidityOutcome:
        if not isinstance(evidence, MedicalImagingValidityEvidence):
            return _input_mismatch(
                self.domain, self.version, MedicalImagingValidityEvidence
            )
        checks: list[DomainCheck] = []
        semantics = evidence.task_semantics
        expected_semantics_type = _MEDICAL_SEMANTICS_TYPES[evidence.task]
        semantics_type_matches = semantics is not None and isinstance(
            semantics, expected_semantics_type
        )
        checks.append(
            _check(
                "MED_TASK_SEMANTICS_INVALID",
                DomainValidityStatus.BLOCKED
                if semantics is None
                else DomainValidityStatus.PASS
                if semantics_type_matches
                else DomainValidityStatus.FAIL,
                "The declared medical task must bind its matching typed task semantics.",
                "protocol.medical_task_semantics",
                "protocol.medical_task_semantics_artifact",
            )
        )
        representation_status = (
            DomainValidityStatus.BLOCKED
            if not semantics_type_matches
            else DomainValidityStatus.PASS
            if _medical_representation_compatible(semantics)
            else DomainValidityStatus.FAIL
        )
        checks.append(
            _check(
                "MED_REPRESENTATION_TASK_INCOMPATIBLE",
                representation_status,
                "2D/3D input, target, and transform representations must be compatible with the task semantics.",
                "protocol.medical_task_semantics",
                "dataset.representation_manifest",
            )
        )
        metric_status = (
            DomainValidityStatus.BLOCKED
            if not semantics_type_matches
            else DomainValidityStatus.PASS
            if _medical_metric_semantics_valid(evidence.task, semantics)
            else DomainValidityStatus.FAIL
        )
        checks.append(
            _check(
                "MED_TASK_METRIC_INVALID",
                metric_status,
                "The primary metric and any registration reference must be valid for the declared task.",
                "protocol.primary_metric",
                "evaluator.metric_semantics",
            )
        )
        expected_metric_direction = (
            _MEDICAL_METRIC_DIRECTIONS.get(_medical_primary_metric(semantics))
            if semantics_type_matches
            else None
        )
        direction_status = (
            DomainValidityStatus.BLOCKED
            if not semantics_type_matches
            else DomainValidityStatus.PASS
            if expected_metric_direction is not None
            and semantics.metric_direction is expected_metric_direction
            else DomainValidityStatus.FAIL
        )
        checks.append(
            _check(
                "MED_METRIC_DIRECTION_INVALID",
                direction_status,
                "Metric direction is derived from the closed medical-metric definition.",
                "protocol.primary_metric",
                "evaluator.metric_direction",
            )
        )
        clinical_context = evidence.clinical_interpretation
        checks.append(
            _check(
                "MED_CLINICAL_INTERPRETATION_MISSING",
                DomainValidityStatus.BLOCKED
                if clinical_context is None
                else DomainValidityStatus.PASS,
                "Clinical use, population, interpretation, and threshold context must be explicit.",
                "protocol.clinical_interpretation",
                "protocol.clinical_context_artifact",
            )
        )
        clinical_use_status = (
            DomainValidityStatus.BLOCKED
            if clinical_context is None
            else DomainValidityStatus.PASS
            if clinical_context.intended_use
            in _MEDICAL_CLINICAL_USES[evidence.task]
            else DomainValidityStatus.FAIL
        )
        checks.append(
            _check(
                "MED_CLINICAL_USE_TASK_MISMATCH",
                clinical_use_status,
                "The intended clinical use must be coherent with the declared task.",
                "protocol.clinical_intended_use",
                "protocol.medical_task_semantics",
            )
        )
        threshold_status = (
            DomainValidityStatus.BLOCKED
            if clinical_context is None or not semantics_type_matches
            else DomainValidityStatus.PASS
            if _medical_threshold_valid(evidence.task, semantics, clinical_context)
            else DomainValidityStatus.FAIL
        )
        checks.append(
            _check(
                "MED_CLINICAL_THRESHOLD_INVALID",
                threshold_status,
                "The clinical threshold basis, unit, relation, and numeric range must match the task and metric; this check does not establish clinical validation.",
                "protocol.clinical_threshold",
                "protocol.primary_metric",
                "protocol.clinical_context_artifact",
            )
        )
        missing_subject_link = any(
            item.patient_id is None and item.subject_id is None
            for item in evidence.observations
        )
        checks.append(
            _check(
                "MED_PATIENT_SUBJECT_LINKAGE_MISSING",
                DomainValidityStatus.BLOCKED
                if missing_subject_link
                else DomainValidityStatus.PASS,
                "Every image must bind to a patient or subject identity.",
                "dataset.image_to_patient_or_subject_manifest",
            )
        )
        subject_leakage = _cross_split(
            evidence.observations, "patient_id"
        ) or _cross_split(evidence.observations, "subject_id")
        checks.append(
            _check(
                "MED_PATIENT_SUBJECT_SPLIT_LEAKAGE",
                DomainValidityStatus.FAIL
                if subject_leakage
                else DomainValidityStatus.PASS,
                "Patient/subject identities must not cross data splits.",
                "dataset.patient_subject_split_manifest",
            )
        )
        patient_subjects: dict[str, set[str]] = {}
        subject_patients: dict[str, set[str]] = {}
        for item in evidence.observations:
            if item.patient_id is None or item.subject_id is None:
                continue
            patient_subjects.setdefault(item.patient_id, set()).add(item.subject_id)
            subject_patients.setdefault(item.subject_id, set()).add(item.patient_id)
        linkage_inconsistent = any(
            len(values) > 1 for values in patient_subjects.values()
        ) or any(len(values) > 1 for values in subject_patients.values())
        checks.append(
            _check(
                "MED_PATIENT_SUBJECT_LINKAGE_INCONSISTENT",
                DomainValidityStatus.FAIL
                if linkage_inconsistent
                else DomainValidityStatus.PASS,
                "Patient-to-subject linkage must be internally consistent.",
                "dataset.patient_subject_linkage",
            )
        )
        for attribute, code, requirement in (
            ("session_id", "MED_SESSION_SPLIT_LEAKAGE", "dataset.session_split_manifest"),
            ("scan_id", "MED_SCAN_SPLIT_LEAKAGE", "dataset.scan_split_manifest"),
        ):
            missing = any(
                getattr(item, attribute) is None for item in evidence.observations
            )
            status = (
                DomainValidityStatus.BLOCKED
                if missing
                else DomainValidityStatus.FAIL
                if _cross_split(evidence.observations, attribute)
                else DomainValidityStatus.PASS
            )
            checks.append(
                _check(
                    code,
                    status,
                    f"{attribute.removesuffix('_id').title()} identities must not cross splits.",
                    requirement,
                )
            )
        site_missing = any(item.site_id is None for item in evidence.observations)
        site_crossing = _cross_split(evidence.observations, "site_id")
        site_status = (
            DomainValidityStatus.BLOCKED
            if site_missing
            else DomainValidityStatus.FAIL
            if evidence.site_disjoint_evaluation_required and site_crossing
            else DomainValidityStatus.PASS
        )
        checks.append(
            _check(
                "MED_SITE_SPLIT_LEAKAGE",
                site_status,
                "Site grouping must match the declared evaluation design.",
                "dataset.site_split_manifest",
                "protocol.site_generalization_design",
            )
        )
        pseudoreplication = (
            evidence.analysis_unit is MedicalAnalysisUnit.SLICE
            and evidence.resampling_unit
            not in {MedicalAnalysisUnit.PATIENT, MedicalAnalysisUnit.SUBJECT}
        )
        checks.append(
            _check(
                "MED_SLICE_PSEUDOREPLICATION",
                DomainValidityStatus.FAIL
                if pseudoreplication
                else DomainValidityStatus.PASS,
                "Slices may not be treated as independent patients or subjects.",
                "protocol.analysis_unit",
                "protocol.resampling_unit",
            )
        )
        checks.extend(
            (
                _documented(
                    evidence.modality_documented,
                    "MED_MODALITY_EVIDENCE_MISSING",
                    "Imaging modality is documented.",
                    "dataset.modality_metadata",
                ),
                _documented(
                    evidence.acquisition_metadata_documented,
                    "MED_ACQUISITION_METADATA_MISSING",
                    "Acquisition and site metadata are documented.",
                    "dataset.acquisition_metadata",
                ),
                _documented(
                    evidence.preprocessing_frozen,
                    "MED_PREPROCESSING_EVIDENCE_MISSING",
                    "Medical-image preprocessing is frozen and split-safe.",
                    "protocol.preprocessing_manifest",
                ),
                _documented(
                    evidence.calibration_evaluated,
                    "MED_CALIBRATION_EVIDENCE_MISSING",
                    "Predictive calibration was evaluated where clinically relevant.",
                    "evaluation.calibration_results",
                ),
                _documented(
                    evidence.uncertainty_evaluated,
                    "MED_UNCERTAINTY_EVIDENCE_MISSING",
                    "Predictive uncertainty was evaluated.",
                    "evaluation.uncertainty_results",
                ),
                _documented(
                    evidence.sensitive_data_controls_documented,
                    "MED_SENSITIVE_DATA_BOUNDARY_MISSING",
                    "Sensitive-data custody and de-identification boundaries are documented.",
                    "security.sensitive_data_controls",
                ),
            )
        )
        evaluated = set(evidence.subgroup_dimensions_evaluated)
        missing_subgroups = tuple(
            item
            for item in evidence.required_subgroup_dimensions
            if item not in evaluated
        )
        checks.append(
            _check(
                "MED_SUBGROUP_EVALUATION_MISSING",
                DomainValidityStatus.BLOCKED
                if missing_subgroups
                else DomainValidityStatus.PASS,
                "Required site and demographic subgroup evaluations must be present.",
                "evaluation.subgroup_results",
                "protocol.required_subgroups",
            )
        )
        if evidence.external_validation_claimed:
            external_status = (
                DomainValidityStatus.BLOCKED
                if evidence.external_validation_performed is None
                else DomainValidityStatus.PASS
                if evidence.external_validation_performed
                else DomainValidityStatus.FAIL
            )
            checks.append(
                _check(
                    "MED_EXTERNAL_VALIDATION_OVERCLAIM",
                    external_status,
                    "External-validation claims require an actually executed external evaluation.",
                    "evaluation.external_site_results",
                    "claim.external_validation_scope",
                )
            )
        return _result(self.domain, self.version, checks)


# ---------------------------------------------------------------------------
# Time series


@dataclass(frozen=True, slots=True)
class TimeSeriesWindow:
    series_id: str
    fold_id: str
    split: SplitRole
    start: float
    end: float

    def __post_init__(self) -> None:
        _validate_text(self.series_id, "series ID")
        _validate_text(self.fold_id, "fold ID")
        if not isinstance(self.split, SplitRole):
            raise DomainInputError("time-series split must be typed")
        _validate_finite(self.start, "window start")
        _validate_finite(self.end, "window end")


@dataclass(frozen=True, slots=True)
class TimeSeriesValidityEvidence:
    windows: tuple[TimeSeriesWindow, ...]
    forecast_horizon_steps: int | None
    evaluated_horizon_steps: int | None
    label_horizon_steps: int | None
    embargo_steps: int | None
    feature_cutoff_verified: bool | None
    drift_assessed: bool | None
    rolling_origin_evaluated: bool | None
    horizon_metrics_reported: bool | None
    evaluator_window_frozen_before_results: bool | None

    def __post_init__(self) -> None:
        _validate_records(self.windows, TimeSeriesWindow, "time-series windows")
        if not self.windows:
            raise DomainInputError("time-series evidence must contain windows")
        for name in (
            "forecast_horizon_steps",
            "evaluated_horizon_steps",
            "label_horizon_steps",
            "embargo_steps",
        ):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int)
            ):
                raise DomainInputError(f"{name} must be integer evidence or unavailable")
        for name in (
            "feature_cutoff_verified",
            "drift_assessed",
            "rolling_origin_evaluated",
            "horizon_metrics_reported",
            "evaluator_window_frozen_before_results",
        ):
            _validate_bool_or_none(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class TimeSeriesAdapter:
    domain: ClassVar[DomainKind] = DomainKind.TIME_SERIES
    version: ClassVar[str] = "1.0"

    def evaluate(self, evidence: object) -> DomainValidityOutcome:
        if not isinstance(evidence, TimeSeriesValidityEvidence):
            return _input_mismatch(self.domain, self.version, TimeSeriesValidityEvidence)
        checks: list[DomainCheck] = []
        invalid_bounds = any(item.start > item.end for item in evidence.windows)
        checks.append(
            _check(
                "TS_WINDOW_BOUNDS_INVALID",
                DomainValidityStatus.FAIL
                if invalid_bounds
                else DomainValidityStatus.PASS,
                "Each temporal window must have ordered finite bounds.",
                "dataset.temporal_windows",
            )
        )
        by_fold_series: dict[tuple[str, str], list[TimeSeriesWindow]] = {}
        for window in evidence.windows:
            by_fold_series.setdefault((window.fold_id, window.series_id), []).append(
                window
            )
        ordering_violation = False
        for values in by_fold_series.values():
            training = [value.end for value in values if value.split is SplitRole.TRAIN]
            evaluation = [
                value.start
                for value in values
                if value.split in {SplitRole.VALIDATION, SplitRole.TEST, SplitRole.HOLDOUT}
            ]
            if training and evaluation and max(training) >= min(evaluation):
                ordering_violation = True
                break
        checks.append(
            _check(
                "TS_TEMPORAL_SPLIT_OVERLAP",
                DomainValidityStatus.FAIL
                if ordering_violation
                else DomainValidityStatus.PASS,
                "Training windows must precede evaluation windows within each fold and series.",
                "dataset.temporal_split_manifest",
            )
        )
        horizon_missing = evidence.forecast_horizon_steps is None
        horizon_invalid = (
            evidence.forecast_horizon_steps is not None
            and evidence.forecast_horizon_steps <= 0
        )
        checks.append(
            _check(
                "TS_FORECAST_HORIZON_INVALID",
                DomainValidityStatus.BLOCKED
                if horizon_missing
                else DomainValidityStatus.FAIL
                if horizon_invalid
                else DomainValidityStatus.PASS,
                "Forecast horizon must be positive and frozen before evaluation.",
                "protocol.forecast_horizon",
            )
        )
        mismatch = (
            evidence.forecast_horizon_steps is not None
            and evidence.evaluated_horizon_steps is not None
            and evidence.forecast_horizon_steps != evidence.evaluated_horizon_steps
        )
        horizon_status = (
            DomainValidityStatus.BLOCKED
            if evidence.evaluated_horizon_steps is None
            else DomainValidityStatus.FAIL
            if mismatch
            else DomainValidityStatus.PASS
        )
        checks.append(
            _check(
                "TS_EVALUATION_HORIZON_MISMATCH",
                horizon_status,
                "Reported metrics must use the frozen forecast horizon.",
                "evaluation.horizon",
                "protocol.forecast_horizon",
            )
        )
        embargo_missing = (
            evidence.label_horizon_steps is None or evidence.embargo_steps is None
        )
        embargo_invalid = (
            not embargo_missing
            and (
                evidence.label_horizon_steps < 0
                or evidence.embargo_steps < 0
                or evidence.embargo_steps < evidence.label_horizon_steps
            )
        )
        checks.append(
            _check(
                "TS_LABEL_HORIZON_LEAKAGE",
                DomainValidityStatus.BLOCKED
                if embargo_missing
                else DomainValidityStatus.FAIL
                if embargo_invalid
                else DomainValidityStatus.PASS,
                "Split embargo must cover the label horizon.",
                "protocol.label_horizon",
                "dataset.split_embargo",
            )
        )
        cutoff_status = (
            DomainValidityStatus.BLOCKED
            if evidence.feature_cutoff_verified is None
            else DomainValidityStatus.PASS
            if evidence.feature_cutoff_verified
            else DomainValidityStatus.FAIL
        )
        checks.append(
            _check(
                "TS_FUTURE_FEATURE_LEAKAGE",
                cutoff_status,
                "Every feature must be available by the prediction cutoff.",
                "dataset.feature_availability_audit",
            )
        )
        checks.extend(
            (
                _documented(
                    evidence.drift_assessed,
                    "TS_DRIFT_EVIDENCE_MISSING",
                    "Temporal drift was measured across evaluation periods.",
                    "evaluation.drift_report",
                ),
                _documented(
                    evidence.rolling_origin_evaluated,
                    "TS_ROLLING_ORIGIN_EVIDENCE_MISSING",
                    "Rolling-origin or equivalent temporal evaluation was performed.",
                    "evaluation.rolling_origin_results",
                ),
                _documented(
                    evidence.horizon_metrics_reported,
                    "TS_HORIZON_METRICS_MISSING",
                    "Metrics are reported by the relevant forecast horizons.",
                    "evaluation.horizon_metrics",
                ),
            )
        )
        evaluator_status = (
            DomainValidityStatus.BLOCKED
            if evidence.evaluator_window_frozen_before_results is None
            else DomainValidityStatus.PASS
            if evidence.evaluator_window_frozen_before_results
            else DomainValidityStatus.FAIL
        )
        checks.append(
            _check(
                "TS_EVALUATOR_WINDOW_GAMING",
                evaluator_status,
                "Evaluation windows must be frozen before results are observed.",
                "evaluator.window_freeze_receipt",
            )
        )
        return _result(self.domain, self.version, checks)


# ---------------------------------------------------------------------------
# Recommender systems


@dataclass(frozen=True, slots=True)
class RecommenderInteraction:
    interaction_id: str
    user_id: str
    item_id: str
    session_id: str
    split: SplitRole
    timestamp: float

    def __post_init__(self) -> None:
        for value, label in (
            (self.interaction_id, "interaction ID"),
            (self.user_id, "user ID"),
            (self.item_id, "item ID"),
            (self.session_id, "session ID"),
        ):
            _validate_text(value, label)
        if not isinstance(self.split, SplitRole):
            raise DomainInputError("recommender split must be typed")
        _validate_finite(self.timestamp, "interaction timestamp")


@dataclass(frozen=True, slots=True)
class RecommenderValidityEvidence:
    interactions: tuple[RecommenderInteraction, ...]
    split_strategy: RecommenderSplitStrategy
    ranking_metrics_verified: bool | None
    candidate_generation_documented: bool | None
    negative_sampling_documented: bool | None
    catalog_coverage_reported: bool | None
    user_coverage_reported: bool | None
    cold_start_evaluated: bool | None
    off_policy_claimed: bool
    propensity_scores_available: bool | None
    support_overlap_verified: bool | None
    heldout_labels_used_for_candidate_generation: bool | None
    evaluator_candidate_set_changed_after_results: bool | None

    def __post_init__(self) -> None:
        _validate_records(
            self.interactions, RecommenderInteraction, "recommender interactions"
        )
        if not self.interactions:
            raise DomainInputError("recommender evidence must contain interactions")
        if not isinstance(self.split_strategy, RecommenderSplitStrategy):
            raise DomainInputError("recommender split strategy must be typed")
        for name in (
            "ranking_metrics_verified",
            "candidate_generation_documented",
            "negative_sampling_documented",
            "catalog_coverage_reported",
            "user_coverage_reported",
            "cold_start_evaluated",
            "propensity_scores_available",
            "support_overlap_verified",
            "heldout_labels_used_for_candidate_generation",
            "evaluator_candidate_set_changed_after_results",
        ):
            _validate_bool_or_none(getattr(self, name), name)
        if not isinstance(self.off_policy_claimed, bool):
            raise DomainInputError("off-policy claim flag must be boolean")


@dataclass(frozen=True, slots=True)
class RecommenderSystemsAdapter:
    domain: ClassVar[DomainKind] = DomainKind.RECOMMENDER_SYSTEMS
    version: ClassVar[str] = "1.0"

    def evaluate(self, evidence: object) -> DomainValidityOutcome:
        if not isinstance(evidence, RecommenderValidityEvidence):
            return _input_mismatch(
                self.domain, self.version, RecommenderValidityEvidence
            )
        checks: list[DomainCheck] = []
        interactions = evidence.interactions
        checks.append(
            _check(
                "REC_INTERACTION_SPLIT_LEAKAGE",
                DomainValidityStatus.FAIL
                if _cross_split(interactions, "interaction_id")
                else DomainValidityStatus.PASS,
                "The same interaction may not appear in multiple splits.",
                "dataset.interaction_split_manifest",
            )
        )
        checks.append(
            _check(
                "REC_SESSION_SPLIT_LEAKAGE",
                DomainValidityStatus.FAIL
                if _cross_split(interactions, "session_id")
                else DomainValidityStatus.PASS,
                "A session must remain within one split.",
                "dataset.session_split_manifest",
            )
        )
        user_leak = (
            evidence.split_strategy is RecommenderSplitStrategy.USER_DISJOINT
            and _cross_split(interactions, "user_id")
        )
        item_leak = (
            evidence.split_strategy is RecommenderSplitStrategy.ITEM_DISJOINT
            and _cross_split(interactions, "item_id")
        )
        checks.append(
            _check(
                "REC_USER_SPLIT_LEAKAGE",
                DomainValidityStatus.FAIL if user_leak else DomainValidityStatus.PASS,
                "User overlap must match the declared split strategy.",
                "dataset.user_split_manifest",
                "protocol.split_strategy",
            )
        )
        checks.append(
            _check(
                "REC_ITEM_SPLIT_LEAKAGE",
                DomainValidityStatus.FAIL if item_leak else DomainValidityStatus.PASS,
                "Item overlap must match the declared split strategy.",
                "dataset.item_split_manifest",
                "protocol.split_strategy",
            )
        )
        temporal_violation = False
        if evidence.split_strategy is RecommenderSplitStrategy.TEMPORAL:
            by_user: dict[str, list[RecommenderInteraction]] = {}
            for interaction in interactions:
                by_user.setdefault(interaction.user_id, []).append(interaction)
            for values in by_user.values():
                training = [
                    item.timestamp for item in values if item.split is SplitRole.TRAIN
                ]
                evaluation = [
                    item.timestamp
                    for item in values
                    if item.split
                    in {SplitRole.VALIDATION, SplitRole.TEST, SplitRole.HOLDOUT}
                ]
                if training and evaluation and max(training) >= min(evaluation):
                    temporal_violation = True
                    break
        checks.append(
            _check(
                "REC_TEMPORAL_ORDER_LEAKAGE",
                DomainValidityStatus.FAIL
                if temporal_violation
                else DomainValidityStatus.PASS,
                "Temporal recommendation splits must preserve per-user chronology.",
                "dataset.interaction_timestamps",
                "protocol.split_strategy",
            )
        )
        checks.extend(
            (
                _documented(
                    evidence.ranking_metrics_verified,
                    "REC_RANKING_EVALUATOR_UNVERIFIED",
                    "Ranking metrics and tie/candidate semantics were verified.",
                    "evaluator.ranking_metric_verification",
                ),
                _documented(
                    evidence.candidate_generation_documented,
                    "REC_CANDIDATE_GENERATION_MISSING",
                    "Candidate-set generation is frozen and documented.",
                    "evaluator.candidate_generation_manifest",
                ),
                _documented(
                    evidence.negative_sampling_documented,
                    "REC_NEGATIVE_SAMPLING_MISSING",
                    "Negative-sampling policy is frozen and documented.",
                    "evaluator.negative_sampling_policy",
                ),
                _documented(
                    evidence.catalog_coverage_reported,
                    "REC_CATALOG_COVERAGE_MISSING",
                    "Catalog coverage was reported.",
                    "evaluation.catalog_coverage",
                ),
                _documented(
                    evidence.user_coverage_reported,
                    "REC_USER_COVERAGE_MISSING",
                    "User coverage was reported.",
                    "evaluation.user_coverage",
                ),
                _documented(
                    evidence.cold_start_evaluated,
                    "REC_COLD_START_EVIDENCE_MISSING",
                    "Cold-start behavior was evaluated.",
                    "evaluation.cold_start_results",
                ),
            )
        )
        if evidence.off_policy_claimed:
            for flag, code, description, requirement in (
                (
                    evidence.propensity_scores_available,
                    "REC_OFF_POLICY_PROPENSITY_MISSING",
                    "Off-policy claims require logged propensities or an equivalent identified design.",
                    "dataset.logging_propensities",
                ),
                (
                    evidence.support_overlap_verified,
                    "REC_OFF_POLICY_SUPPORT_MISSING",
                    "Off-policy claims require support-overlap diagnostics.",
                    "evaluation.support_overlap",
                ),
            ):
                checks.append(_documented(flag, code, description, requirement))
        heldout_status = (
            DomainValidityStatus.BLOCKED
            if evidence.heldout_labels_used_for_candidate_generation is None
            else DomainValidityStatus.FAIL
            if evidence.heldout_labels_used_for_candidate_generation
            else DomainValidityStatus.PASS
        )
        checks.append(
            _check(
                "REC_HELDOUT_LABEL_LEAKAGE",
                heldout_status,
                "Held-out labels may not influence candidate generation.",
                "evaluator.candidate_label_access_audit",
            )
        )
        gaming_status = (
            DomainValidityStatus.BLOCKED
            if evidence.evaluator_candidate_set_changed_after_results is None
            else DomainValidityStatus.FAIL
            if evidence.evaluator_candidate_set_changed_after_results
            else DomainValidityStatus.PASS
        )
        checks.append(
            _check(
                "REC_EVALUATOR_EXPLOITATION",
                gaming_status,
                "The candidate set and evaluator must be frozen before results.",
                "evaluator.freeze_receipt",
                "evaluator.candidate_set_hash",
            )
        )
        return _result(self.domain, self.version, checks)


# ---------------------------------------------------------------------------
# Operations research / optimization


@dataclass(frozen=True, slots=True)
class OptimizationInstanceResult:
    instance_id: str
    candidate_feasible: bool | None
    baseline_feasible: bool | None
    candidate_objective: float | None
    baseline_objective: float | None
    best_bound: float | None
    candidate_claimed_better: bool
    candidate_claimed_optimal: bool = False

    def __post_init__(self) -> None:
        _validate_text(self.instance_id, "optimization instance ID")
        _validate_bool_or_none(self.candidate_feasible, "candidate feasibility")
        _validate_bool_or_none(self.baseline_feasible, "baseline feasibility")
        for name in ("candidate_objective", "baseline_objective", "best_bound"):
            _validate_finite(getattr(self, name), name)
        if not isinstance(self.candidate_claimed_better, bool) or not isinstance(
            self.candidate_claimed_optimal, bool
        ):
            raise DomainInputError("optimization claim flags must be boolean")


@dataclass(frozen=True, slots=True)
class OperationsResearchValidityEvidence:
    instances: tuple[OptimizationInstanceResult, ...]
    objective_direction: ObjectiveDirection
    objective_and_constraints_validated: bool | None
    paired_instances_verified: bool | None
    exact_baseline_required: bool
    exact_baseline_run: bool | None
    central_superiority_claimed: bool
    solver_version: str | None
    timeout_policy_equivalent: bool | None
    machine_specification_equivalent: bool | None
    random_instance_generator_frozen: bool | None
    scalability_evaluated: bool | None
    runtime_quality_tradeoff_reported: bool | None
    optimality_gap_reported: bool | None
    excluded_failures: int = 0
    failure_exclusion_justified: bool | None = True
    evaluator_objective_changed_after_results: bool | None = False
    optimality_tolerance: float = 0.0

    def __post_init__(self) -> None:
        _validate_records(
            self.instances, OptimizationInstanceResult, "optimization instances"
        )
        if not self.instances:
            raise DomainInputError("optimization evidence must contain instances")
        if not isinstance(self.objective_direction, ObjectiveDirection):
            raise DomainInputError("objective direction must be typed")
        for name in (
            "objective_and_constraints_validated",
            "paired_instances_verified",
            "exact_baseline_run",
            "timeout_policy_equivalent",
            "machine_specification_equivalent",
            "random_instance_generator_frozen",
            "scalability_evaluated",
            "runtime_quality_tradeoff_reported",
            "optimality_gap_reported",
            "failure_exclusion_justified",
            "evaluator_objective_changed_after_results",
        ):
            _validate_bool_or_none(getattr(self, name), name)
        if not isinstance(self.exact_baseline_required, bool) or not isinstance(
            self.central_superiority_claimed, bool
        ):
            raise DomainInputError("optimization policy flags must be boolean")
        _validate_optional_text(self.solver_version, "solver version")
        _validate_count(self.excluded_failures, "excluded failure count")
        _validate_finite(self.optimality_tolerance, "optimality tolerance")
        if self.optimality_tolerance < 0:
            raise DomainInputError("optimality tolerance must be non-negative")


@dataclass(frozen=True, slots=True)
class OperationsResearchAdapter:
    domain: ClassVar[DomainKind] = DomainKind.OPERATIONS_RESEARCH
    version: ClassVar[str] = "1.0"

    def evaluate(self, evidence: object) -> DomainValidityOutcome:
        if not isinstance(evidence, OperationsResearchValidityEvidence):
            return _input_mismatch(
                self.domain, self.version, OperationsResearchValidityEvidence
            )
        checks: list[DomainCheck] = []
        checks.append(
            _documented(
                evidence.objective_and_constraints_validated,
                "OR_OBJECTIVE_CONSTRAINT_VALIDATION_MISSING",
                "Objective and constraint semantics were validated.",
                "protocol.objective_and_constraints",
            )
        )
        missing_feasibility = any(
            item.candidate_feasible is None or item.baseline_feasible is None
            for item in evidence.instances
        )
        infeasible_claim = any(
            item.candidate_feasible is False
            and (item.candidate_claimed_better or item.candidate_claimed_optimal)
            for item in evidence.instances
        )
        checks.append(
            _check(
                "OR_INFEASIBLE_RESULT_PROMOTED",
                DomainValidityStatus.BLOCKED
                if missing_feasibility
                else DomainValidityStatus.FAIL
                if infeasible_claim
                else DomainValidityStatus.PASS,
                "Infeasible solutions cannot support quality or optimality claims.",
                "evaluation.feasibility_results",
            )
        )
        missing_objective = any(
            item.candidate_objective is None or item.baseline_objective is None
            for item in evidence.instances
        )
        wrong_direction = False
        if not missing_objective:
            for item in evidence.instances:
                assert item.candidate_objective is not None
                assert item.baseline_objective is not None
                better = (
                    item.candidate_objective < item.baseline_objective
                    if evidence.objective_direction is ObjectiveDirection.MINIMIZE
                    else item.candidate_objective > item.baseline_objective
                )
                if item.candidate_claimed_better and not better:
                    wrong_direction = True
                    break
        checks.append(
            _check(
                "OR_OBJECTIVE_DIRECTION_MISMATCH",
                DomainValidityStatus.BLOCKED
                if missing_objective
                else DomainValidityStatus.FAIL
                if wrong_direction
                else DomainValidityStatus.PASS,
                "Claimed wins must respect the frozen objective direction.",
                "protocol.objective_direction",
                "evaluation.paired_objectives",
            )
        )
        invalid_optimality = False
        missing_bound = False
        for item in evidence.instances:
            if not item.candidate_claimed_optimal:
                continue
            if item.candidate_objective is None or item.best_bound is None:
                missing_bound = True
                continue
            raw_gap = (
                item.candidate_objective - item.best_bound
                if evidence.objective_direction is ObjectiveDirection.MINIMIZE
                else item.best_bound - item.candidate_objective
            )
            if raw_gap < -evidence.optimality_tolerance or raw_gap > evidence.optimality_tolerance:
                invalid_optimality = True
        checks.append(
            _check(
                "OR_OPTIMALITY_CLAIM_UNSUPPORTED",
                DomainValidityStatus.FAIL
                if invalid_optimality
                else DomainValidityStatus.BLOCKED
                if missing_bound
                else DomainValidityStatus.PASS,
                "Optimality claims require compatible bounds within frozen tolerance.",
                "evaluation.optimality_bounds",
                "protocol.optimality_tolerance",
            )
        )
        paired_status = (
            DomainValidityStatus.BLOCKED
            if evidence.paired_instances_verified is None
            else DomainValidityStatus.PASS
            if evidence.paired_instances_verified
            else DomainValidityStatus.FAIL
        )
        checks.append(
            _check(
                "OR_PAIRED_INSTANCE_COMPARISON_INVALID",
                paired_status,
                "Candidate and baselines must run on paired instances.",
                "evaluation.paired_instance_manifest",
            )
        )
        if evidence.exact_baseline_required:
            baseline_status = (
                DomainValidityStatus.BLOCKED
                if evidence.exact_baseline_run is None
                else DomainValidityStatus.PASS
                if evidence.exact_baseline_run
                else DomainValidityStatus.FAIL
                if evidence.central_superiority_claimed
                else DomainValidityStatus.BLOCKED
            )
            checks.append(
                _check(
                    "OR_REQUIRED_EXACT_BASELINE_OMITTED",
                    baseline_status,
                    "Required exact baselines must be run before superiority claims.",
                    "baseline.exact_solver_result",
                    "baseline.registry_status",
                )
            )
        checks.append(
            _check(
                "OR_SOLVER_VERSION_MISSING",
                DomainValidityStatus.PASS
                if evidence.solver_version
                else DomainValidityStatus.BLOCKED,
                "Solver identity and version must be recorded.",
                "environment.solver_version",
            )
        )
        for flag, code, description, requirement in (
            (
                evidence.timeout_policy_equivalent,
                "OR_TIMEOUT_POLICY_UNFAIR",
                "Candidate and baseline timeout policies are equivalent.",
                "baseline.timeout_policy_comparison",
            ),
            (
                evidence.machine_specification_equivalent,
                "OR_MACHINE_SPEC_UNFAIR",
                "Candidate and baseline machine specifications are equivalent.",
                "baseline.machine_specification_comparison",
            ),
        ):
            status = (
                DomainValidityStatus.BLOCKED
                if flag is None
                else DomainValidityStatus.PASS
                if flag
                else DomainValidityStatus.FAIL
            )
            checks.append(_check(code, status, description, requirement))
        checks.extend(
            (
                _documented(
                    evidence.random_instance_generator_frozen,
                    "OR_RANDOM_INSTANCE_POLICY_MISSING",
                    "Random-instance generator and seeds are frozen.",
                    "protocol.random_instance_generator",
                ),
                _documented(
                    evidence.scalability_evaluated,
                    "OR_SCALABILITY_EVIDENCE_MISSING",
                    "Scalability was evaluated across relevant instance sizes.",
                    "evaluation.scalability_results",
                ),
                _documented(
                    evidence.runtime_quality_tradeoff_reported,
                    "OR_RUNTIME_QUALITY_TRADEOFF_MISSING",
                    "Runtime-quality tradeoffs are reported.",
                    "evaluation.runtime_quality_tradeoff",
                ),
                _documented(
                    evidence.optimality_gap_reported,
                    "OR_OPTIMALITY_GAP_REPORT_MISSING",
                    "Optimality gaps and bounds are reported where applicable.",
                    "evaluation.optimality_gap_report",
                ),
            )
        )
        excluded_status = (
            DomainValidityStatus.PASS
            if evidence.excluded_failures == 0
            else DomainValidityStatus.BLOCKED
            if evidence.failure_exclusion_justified is None
            else DomainValidityStatus.PASS
            if evidence.failure_exclusion_justified
            else DomainValidityStatus.FAIL
        )
        checks.append(
            _check(
                "OR_SELECTIVE_FAILURE_REPORTING",
                excluded_status,
                "Timeouts, failures, and invalid runs must not be selectively omitted.",
                "evaluation.all_instance_outcomes",
                "evaluation.exclusion_justification",
            )
        )
        gaming_status = (
            DomainValidityStatus.BLOCKED
            if evidence.evaluator_objective_changed_after_results is None
            else DomainValidityStatus.FAIL
            if evidence.evaluator_objective_changed_after_results
            else DomainValidityStatus.PASS
        )
        checks.append(
            _check(
                "OR_EVALUATOR_OBJECTIVE_GAMING",
                gaming_status,
                "Objective/evaluator semantics must be frozen before results.",
                "evaluator.objective_freeze_receipt",
            )
        )
        return _result(self.domain, self.version, checks)


# ---------------------------------------------------------------------------
# Systems


@dataclass(frozen=True, slots=True)
class SystemsMeasurement:
    metric_name: str
    scope: MetricScope
    direction: MetricDirection
    candidate_values: tuple[float, ...]
    baseline_values: tuple[float, ...]
    candidate_claimed_better: bool

    def __post_init__(self) -> None:
        _validate_text(self.metric_name, "systems metric name")
        if not isinstance(self.scope, MetricScope) or not isinstance(
            self.direction, MetricDirection
        ):
            raise DomainInputError("systems metric semantics must be typed")
        _validate_float_tuple(self.candidate_values, "candidate measurements")
        _validate_float_tuple(self.baseline_values, "baseline measurements")
        if not isinstance(self.candidate_claimed_better, bool):
            raise DomainInputError("systems metric claim flag must be boolean")


@dataclass(frozen=True, slots=True)
class SystemsValidityEvidence:
    measurements: tuple[SystemsMeasurement, ...]
    claim_scope: SystemsClaimScope
    hardware_identity: str | None
    os_kernel_stack: str | None
    software_stack: str | None
    workload_manifest: str | None
    workload_validated: bool | None
    warmup_completed: bool | None
    resource_isolation_verified: bool | None
    concurrency_documented: bool | None
    hardware_equivalent: bool | None
    runtime_environment_equivalent: bool | None
    tail_latency_reported: bool | None
    memory_reported: bool | None
    energy_relevant: bool
    energy_reported: bool | None
    evaluator_frozen_before_results: bool | None
    evaluator_observable_to_candidate: bool | None
    evaluator_specific_branching_detected: bool | None
    excluded_runs: int = 0
    exclusion_justified: bool | None = True
    maximum_coefficient_of_variation: float = 0.20

    def __post_init__(self) -> None:
        _validate_records(self.measurements, SystemsMeasurement, "systems measurements")
        if not self.measurements:
            raise DomainInputError("systems evidence must contain measurements")
        if not isinstance(self.claim_scope, SystemsClaimScope):
            raise DomainInputError("systems claim scope must be typed")
        for name in (
            "hardware_identity",
            "os_kernel_stack",
            "software_stack",
            "workload_manifest",
        ):
            _validate_optional_text(getattr(self, name), name)
        for name in (
            "workload_validated",
            "warmup_completed",
            "resource_isolation_verified",
            "concurrency_documented",
            "hardware_equivalent",
            "runtime_environment_equivalent",
            "tail_latency_reported",
            "memory_reported",
            "energy_reported",
            "evaluator_frozen_before_results",
            "evaluator_observable_to_candidate",
            "evaluator_specific_branching_detected",
            "exclusion_justified",
        ):
            _validate_bool_or_none(getattr(self, name), name)
        if not isinstance(self.energy_relevant, bool):
            raise DomainInputError("energy relevance flag must be boolean")
        _validate_count(self.excluded_runs, "excluded run count")
        _validate_finite(
            self.maximum_coefficient_of_variation,
            "maximum coefficient of variation",
        )
        if self.maximum_coefficient_of_variation < 0:
            raise DomainInputError("variance threshold must be non-negative")


@dataclass(frozen=True, slots=True)
class SystemsAdapter:
    domain: ClassVar[DomainKind] = DomainKind.SYSTEMS
    version: ClassVar[str] = "1.0"

    def evaluate(self, evidence: object) -> DomainValidityOutcome:
        if not isinstance(evidence, SystemsValidityEvidence):
            return _input_mismatch(self.domain, self.version, SystemsValidityEvidence)
        checks: list[DomainCheck] = []
        for value, code, description, requirement in (
            (
                evidence.hardware_identity,
                "SYS_HARDWARE_IDENTITY_MISSING",
                "Exact hardware identity is recorded.",
                "environment.hardware_identity",
            ),
            (
                evidence.os_kernel_stack,
                "SYS_OS_KERNEL_STACK_MISSING",
                "OS and kernel identity are recorded.",
                "environment.os_kernel_stack",
            ),
            (
                evidence.software_stack,
                "SYS_SOFTWARE_STACK_MISSING",
                "Software/runtime stack is recorded.",
                "environment.software_stack",
            ),
            (
                evidence.workload_manifest,
                "SYS_WORKLOAD_MANIFEST_MISSING",
                "Workload identity and configuration are frozen.",
                "workload.manifest",
            ),
        ):
            checks.append(
                _check(
                    code,
                    DomainValidityStatus.PASS
                    if value
                    else DomainValidityStatus.BLOCKED,
                    description,
                    requirement,
                )
            )
        workload_status = (
            DomainValidityStatus.BLOCKED
            if evidence.workload_validated is None
            else DomainValidityStatus.PASS
            if evidence.workload_validated
            else DomainValidityStatus.FAIL
        )
        checks.append(
            _check(
                "SYS_WORKLOAD_INVALID",
                workload_status,
                "Benchmark workload must represent the claimed operating regime.",
                "workload.validity_assessment",
            )
        )
        proxy_promoted = (
            evidence.claim_scope is SystemsClaimScope.SYSTEM_LEVEL
            and not any(
                measurement.scope is MetricScope.END_TO_END
                for measurement in evidence.measurements
            )
        )
        checks.append(
            _check(
                "SYS_PROXY_PROMOTED_TO_SYSTEM_CLAIM",
                DomainValidityStatus.FAIL
                if proxy_promoted
                else DomainValidityStatus.PASS,
                "System-level claims require end-to-end measurements, not proxies alone.",
                "claim.metric_scope",
                "evaluation.end_to_end_measurements",
            )
        )
        insufficient_repeats = any(
            len(measurement.candidate_values) < 3
            or len(measurement.baseline_values) < 3
            for measurement in evidence.measurements
        )
        checks.append(
            _check(
                "SYS_REPEATED_MEASUREMENTS_MISSING",
                DomainValidityStatus.BLOCKED
                if insufficient_repeats
                else DomainValidityStatus.PASS,
                "Candidate and baseline require repeated measurements.",
                "evaluation.raw_repeated_measurements",
            )
        )
        excessive_variance = False
        for measurement in evidence.measurements:
            for values in (measurement.candidate_values, measurement.baseline_values):
                if len(values) < 2:
                    continue
                mean = fmean(values)
                coefficient = math.inf if mean == 0 and pstdev(values) > 0 else (
                    0.0 if mean == 0 else pstdev(values) / abs(mean)
                )
                if coefficient > evidence.maximum_coefficient_of_variation:
                    excessive_variance = True
        checks.append(
            _check(
                "SYS_RUNTIME_VARIANCE_EXCESSIVE",
                DomainValidityStatus.BLOCKED
                if excessive_variance
                else DomainValidityStatus.PASS,
                "Runtime variance must be within the frozen stability threshold.",
                "evaluation.variance_analysis",
                "protocol.variance_threshold",
            )
        )
        direction_mismatch = False
        for measurement in evidence.measurements:
            if not measurement.candidate_values or not measurement.baseline_values:
                continue
            candidate = fmean(measurement.candidate_values)
            baseline = fmean(measurement.baseline_values)
            better = (
                candidate < baseline
                if measurement.direction is MetricDirection.LOWER_IS_BETTER
                else candidate > baseline
            )
            if measurement.candidate_claimed_better and not better:
                direction_mismatch = True
                break
        checks.append(
            _check(
                "SYS_METRIC_DIRECTION_MISMATCH",
                DomainValidityStatus.FAIL
                if direction_mismatch
                else DomainValidityStatus.PASS,
                "Claimed improvements must respect each metric's frozen direction.",
                "protocol.metric_direction",
                "evaluation.raw_repeated_measurements",
            )
        )
        for flag, code, description, requirement, false_status in (
            (
                evidence.warmup_completed,
                "SYS_WARMUP_MISSING",
                "Required warmup completed before timed measurements.",
                "evaluation.warmup_log",
                DomainValidityStatus.FAIL,
            ),
            (
                evidence.resource_isolation_verified,
                "SYS_RESOURCE_ISOLATION_MISSING",
                "Resource isolation and background load were verified.",
                "environment.resource_isolation",
                DomainValidityStatus.FAIL,
            ),
            (
                evidence.concurrency_documented,
                "SYS_CONCURRENCY_CONFIGURATION_MISSING",
                "Concurrency configuration is frozen and documented.",
                "workload.concurrency_configuration",
                DomainValidityStatus.BLOCKED,
            ),
            (
                evidence.hardware_equivalent,
                "SYS_HARDWARE_COMPARISON_UNFAIR",
                "Candidate and baseline hardware are equivalent or normalized.",
                "baseline.hardware_comparison",
                DomainValidityStatus.FAIL,
            ),
            (
                evidence.runtime_environment_equivalent,
                "SYS_RUNTIME_COMPARISON_UNFAIR",
                "Candidate and baseline runtime environments are equivalent.",
                "baseline.runtime_environment_comparison",
                DomainValidityStatus.FAIL,
            ),
        ):
            status = (
                DomainValidityStatus.BLOCKED
                if flag is None
                else DomainValidityStatus.PASS
                if flag
                else false_status
            )
            checks.append(_check(code, status, description, requirement))
        checks.extend(
            (
                _documented(
                    evidence.tail_latency_reported,
                    "SYS_TAIL_LATENCY_MISSING",
                    "Tail latency is reported where latency is material.",
                    "evaluation.tail_latency",
                ),
                _documented(
                    evidence.memory_reported,
                    "SYS_MEMORY_EVIDENCE_MISSING",
                    "Memory consumption is reported.",
                    "evaluation.memory_results",
                ),
            )
        )
        if evidence.energy_relevant:
            checks.append(
                _documented(
                    evidence.energy_reported,
                    "SYS_ENERGY_EVIDENCE_MISSING",
                    "Energy is reported because it is material to the claim.",
                    "evaluation.energy_results",
                )
            )
        frozen_status = (
            DomainValidityStatus.BLOCKED
            if evidence.evaluator_frozen_before_results is None
            else DomainValidityStatus.PASS
            if evidence.evaluator_frozen_before_results
            else DomainValidityStatus.FAIL
        )
        checks.append(
            _check(
                "SYS_EVALUATOR_NOT_FROZEN",
                frozen_status,
                "The evaluator and workload must be frozen before results.",
                "evaluator.freeze_receipt",
            )
        )
        exploit_unknown = (
            evidence.evaluator_observable_to_candidate is None
            or evidence.evaluator_specific_branching_detected is None
        )
        exploit_detected = (
            evidence.evaluator_observable_to_candidate is True
            or evidence.evaluator_specific_branching_detected is True
        )
        checks.append(
            _check(
                "SYS_EVALUATOR_EXPLOITATION",
                DomainValidityStatus.FAIL
                if exploit_detected
                else DomainValidityStatus.BLOCKED
                if exploit_unknown
                else DomainValidityStatus.PASS,
                "Candidate execution must not observe or branch on evaluator internals.",
                "evaluator.access_audit",
                "implementation.evaluator_branch_scan",
            )
        )
        exclusion_status = (
            DomainValidityStatus.PASS
            if evidence.excluded_runs == 0
            else DomainValidityStatus.BLOCKED
            if evidence.exclusion_justified is None
            else DomainValidityStatus.PASS
            if evidence.exclusion_justified
            else DomainValidityStatus.FAIL
        )
        checks.append(
            _check(
                "SYS_SELECTIVE_RUN_REPORTING",
                exclusion_status,
                "All failed, timed-out, and excluded benchmark runs must remain visible.",
                "evaluation.all_run_outcomes",
                "evaluation.exclusion_justification",
            )
        )
        return _result(self.domain, self.version, checks)


DOMAIN_ADAPTERS: tuple[DomainAdapter, ...] = (
    GenericMLAdapter(),
    MedicalImagingAdapter(),
    TimeSeriesAdapter(),
    RecommenderSystemsAdapter(),
    OperationsResearchAdapter(),
    SystemsAdapter(),
)


def get_domain_adapter(domain: DomainKind) -> DomainAdapter:
    if not isinstance(domain, DomainKind):
        raise DomainInputError("domain adapter lookup requires a typed domain")
    for adapter in DOMAIN_ADAPTERS:
        if adapter.domain is domain:
            return adapter
    raise DomainInputError(f"no adapter registered for {domain.value}")


# ---------------------------------------------------------------------------
# Registry-resolved domain replay authority


_DOMAIN_RAW_SOURCE_COMMAND = ("scientist-one", "register-domain-raw-fixture-source")
_DOMAIN_SOURCE_COMMAND = ("scientist-one", "register-domain-evidence-source")
_DOMAIN_MANIFEST_COMMAND = ("scientist-one", "materialize-domain-evidence-manifest")
_DOMAIN_RECEIPT_COMMAND = ("scientist-one", "materialize-domain-validity-receipt")
_SCIENTIFIC_DOMAIN_PLAN_COMMAND = (
    "scientist-one",
    "register-scientific-domain-evidence-plan",
)
_SCIENTIFIC_DOMAIN_SOURCE_COMMAND = (
    "scientist-one",
    "register-scientific-domain-evidence-source",
)
_SCIENTIFIC_DOMAIN_MATERIALIZATION_COMMAND = (
    "scientist-one",
    "materialize-scientific-domain-validity",
)
_SCIENTIFIC_DOMAIN_PLAN_EVENT_SCHEMA = "scientific-domain-plan-event/v1"
_SCIENTIFIC_DOMAIN_SOURCE_EVENT_SCHEMA = "scientific-domain-source-event/v1"
_SCIENTIFIC_DOMAIN_VALIDITY_EVENT_SCHEMA = "scientific-domain-validity-event/v1"
_SCIENTIFIC_DOMAIN_VALIDITY_EVENT_SCHEMA_V2 = (
    "scientific-domain-validity-event/v2"
)
_SCIENTIFIC_DOMAIN_TRUST_REVOCATION_EVENT_SCHEMA = (
    "scientific-domain-trust-root-revocation-event/v1"
)
SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID = (
    "trusted-kernel-generic-ml-observations"
)
SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION = "1.0"
SCIENTIFIC_DOMAIN_GENERIC_ML_ATTESTATION_SCHEMA = (
    "trusted-kernel-generic-ml-hmac-sha256/v1"
)
SCIENTIFIC_DOMAIN_GENERIC_ML_VERIFIER_ID = (
    "scientist-one-generic-ml-observation-verifier/v1"
)
SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME = (
    ".scientific-domain-generic-ml-observations-" + "authority.key"
)
# Operational custody invariant: provisioning must generate unique bytes for
# each run-scoped registry and must never copy them between runs.  This bounded
# per-run ledger cannot prove or globally revoke cross-registry key reuse.
_SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BYTES = 32
_SCIENTIFIC_DOMAIN_GENERIC_ML_POLICY_SCHEMA = (
    "trusted-kernel-reference-accuracy/v1"
)
_SCIENTIFIC_DOMAIN_GENERIC_ML_PREDICTIONS_SCHEMA = (
    "trusted-kernel-generic-ml-predictions/v1"
)
_SCIENTIFIC_DOMAIN_GENERIC_ML_ROBUSTNESS_SCHEMA = (
    "trusted-kernel-generic-ml-robustness/v1"
)
# Separate short registry schema IDs from unchanged content format IDs.
# ArtifactRecord rejects metadata schema strings longer than32 characters.
_SCIENTIFIC_DOMAIN_GENERIC_ML_PREDICTIONS_ARTIFACT_SCHEMA = "generic-ml-predictions/v1"
_SCIENTIFIC_DOMAIN_GENERIC_ML_ROBUSTNESS_ARTIFACT_SCHEMA = "generic-ml-robustness/v1"
_SCIENTIFIC_DOMAIN_GENERIC_ML_PRETRAINED_INVENTORY_SCHEMA = (
    "trusted-kernel-loaded-pretrained-inventory/v1"
)
_DOMAIN_RAW_SOURCE_ROLES = frozenset(
    {
        Role.PROTOCOL_DESIGNER,
        Role.EVIDENCE_CURATOR,
        Role.EXPERIMENT_RUNNER,
        Role.SCIENTIFIC_REVIEWER,
    }
)


@dataclass(frozen=True, slots=True)
class ResolvedDomainValidity:
    """One freshly replayed, registry-bound domain-validity receipt.

    ``scope`` is deliberately separate from ``outcome``.  A fixture may prove
    that an adapter deterministically returns PASS without becoming scientific
    evidence or authorizing a gate.
    """

    receipt_artifact_sha256: str
    manifest_artifact_sha256: str
    source_artifact_hashes: tuple[str, ...]
    run_id: str
    domain: DomainKind
    object_id: str
    task_id: str
    scope: DomainEvidenceScope
    limitations: tuple[DomainValidityLimitation, ...]
    evidence: object
    outcome: DomainValidityOutcome
    projection_artifact_sha256: str | None = None

    def __post_init__(self) -> None:
        _validate_sha256(self.receipt_artifact_sha256, "domain receipt artifact")
        _validate_sha256(self.manifest_artifact_sha256, "domain manifest artifact")
        _validate_hash_tuple(
            self.source_artifact_hashes,
            "domain source artifacts",
            maximum=257,
        )
        validate_identifier(self.run_id, "domain run ID")
        validate_identifier(self.object_id, "domain object ID")
        validate_identifier(self.task_id, "domain task ID")
        if not isinstance(self.domain, DomainKind):
            raise DomainInputError("resolved domain kind must be typed")
        if not isinstance(self.scope, DomainEvidenceScope):
            raise DomainInputError("resolved domain evidence scope must be typed")
        if (
            not isinstance(self.limitations, tuple)
            or any(
                not isinstance(value, DomainValidityLimitation)
                for value in self.limitations
            )
            or len(set(self.limitations)) != len(self.limitations)
        ):
            raise DomainInputError("resolved domain limitations must be unique and typed")
        if (
            self.scope is DomainEvidenceScope.NON_EVIDENTIARY_FIXTURE
            and not self.limitations
        ):
            raise DomainInputError("fixture domain validity must retain its limitations")
        if (
            self.scope is DomainEvidenceScope.SCIENTIFIC_EVIDENCE
            and self.limitations
        ):
            raise DomainInputError(
                "scientific domain validity cannot carry fixture limitations"
            )
        if type(self.evidence) is GenericMLFixedModelValidityEvidence:
            if (
                self.domain is not DomainKind.GENERIC_ML
                or self.scope is not DomainEvidenceScope.SCIENTIFIC_EVIDENCE
                or type(self.projection_artifact_sha256) is not str
                or type(self.outcome) is not DomainValidityOutcome
                or type(self.outcome.adapter_version) is not str
                or self.outcome.adapter_version != GenericMLFixedModelAdapter.version
            ):
                raise DomainInputError("fixed-model resolved domain requires its exact scientific projection profile")
            replace(self.evidence)
        else:
            expected_type = _domain_evidence_type(self.domain)
            if type(self.evidence) is not expected_type:
                raise DomainInputError("resolved domain evidence type does not match its domain")
        if (
            not isinstance(self.outcome, DomainValidityOutcome)
            or self.outcome.domain is not self.domain
        ):
            raise DomainInputError("resolved domain outcome does not match its domain")
        if self.projection_artifact_sha256 is not None:
            _validate_sha256(
                self.projection_artifact_sha256,
                "resolved domain paired projection",
            )


@dataclass(frozen=True, slots=True)
class _ResolvedDomainSource:
    record: ArtifactRecord
    run_id: str
    domain: DomainKind
    object_id: str
    task_id: str
    scope: DomainEvidenceScope
    limitations: tuple[DomainValidityLimitation, ...]
    supporting_artifact_hashes: tuple[str, ...]
    evidence_payload_sha256: str
    evidence: object


@dataclass(frozen=True, slots=True)
class ScientificDomainEvidenceSourceAuthority:
    """Public fresh-replay view of one pre-assessment scientific source."""

    source_artifact_sha256: str
    source_record_hash: str
    plan_artifact_sha256: str
    plan_record_hash: str
    raw_source_artifact_sha256: str
    raw_source_record_hash: str
    scientific_execution_authority_artifact_sha256: str
    scientific_execution_authority_record_hash: str
    canonical_run_artifact_sha256: str
    canonical_run_record_hash: str
    canonical_run_content_hash: str
    run_id: str
    execution_run_id: str
    domain: DomainKind
    object_id: str
    task_id: str
    source_format_id: str
    source_format_version: str
    evaluation_contract_artifact_sha256: str
    evaluation_contract_record_hash: str
    dataset_authority_artifact_sha256: str
    dataset_authority_record_hash: str
    split_authority_artifact_sha256s: tuple[str, ...]
    split_authority_record_hashes: tuple[str, ...]
    frozen_run_spec_artifact_sha256: str
    frozen_run_spec_record_hash: str
    evidence_payload_sha256: str
    evidence: object
    supporting_artifact_sha256s: tuple[str, ...]
    supporting_artifact_record_hashes: tuple[str, ...]
    source_event_id: str
    source_event_hash: str
    source_event_index: int


@dataclass(frozen=True, slots=True)
class ScientificDomainEvidencePlan:
    """Prospective binding for one closed domain source profile and run."""

    plan_artifact_sha256: str
    plan_record_hash: str
    run_id: str
    domain: DomainKind
    object_id: str
    task_id: str
    source_format_id: str
    source_format_version: str
    attestation_schema: str
    verifier_id: str
    trust_root_id: str
    evaluation_contract_artifact_sha256: str
    evaluation_contract_record_hash: str
    dataset_authority_artifact_sha256: str
    dataset_authority_record_hash: str
    split_authority_artifact_sha256s: tuple[str, ...]
    split_authority_record_hashes: tuple[str, ...]
    frozen_run_spec_artifact_sha256: str
    frozen_run_spec_record_hash: str
    execution_run_id: str
    ledger_event_id: str
    ledger_event_hash: str
    ledger_event_index: int

    def __post_init__(self) -> None:
        for value, label in (
            (self.plan_artifact_sha256, "scientific domain plan artifact"),
            (self.plan_record_hash, "scientific domain plan record"),
            (
                self.evaluation_contract_artifact_sha256,
                "scientific domain plan evaluation contract",
            ),
            (
                self.evaluation_contract_record_hash,
                "scientific domain plan evaluation-contract record",
            ),
            (
                self.dataset_authority_artifact_sha256,
                "scientific domain plan Dataset authority",
            ),
            (
                self.dataset_authority_record_hash,
                "scientific domain plan Dataset-authority record",
            ),
            (
                self.frozen_run_spec_artifact_sha256,
                "scientific domain plan frozen run spec",
            ),
            (
                self.frozen_run_spec_record_hash,
                "scientific domain plan frozen-run-spec record",
            ),
            (self.ledger_event_hash, "scientific domain plan ledger event"),
        ):
            _validate_sha256(value, label)
        _validate_hash_tuple(
            self.split_authority_artifact_sha256s,
            "scientific domain plan split authorities",
            maximum=4,
        )
        _validate_hash_tuple(
            self.split_authority_record_hashes,
            "scientific domain plan split-authority records",
            maximum=4,
        )
        if len(self.split_authority_artifact_sha256s) != 4 or len(
            self.split_authority_record_hashes
        ) != len(self.split_authority_artifact_sha256s):
            raise DomainInputError(
                "scientific domain plan requires four exact split authorities"
            )
        for value, label in (
            (self.run_id, "scientific domain plan run ID"),
            (self.object_id, "scientific domain plan object ID"),
            (self.task_id, "scientific domain plan task ID"),
            (self.execution_run_id, "scientific domain execution run ID"),
            (self.ledger_event_id, "scientific domain plan event ID"),
        ):
            validate_identifier(value, label)
        if not isinstance(self.domain, DomainKind):
            raise DomainInputError("scientific domain plan kind must be typed")
        if (
            not isinstance(self.source_format_id, str)
            or not _RAW_SOURCE_ID_RE.fullmatch(self.source_format_id)
        ):
            raise DomainInputError("scientific domain source-format ID is invalid")
        _validate_text(
            self.source_format_version,
            "scientific domain source-format version",
        )
        _validate_text(
            self.attestation_schema,
            "scientific domain attestation schema",
        )
        _validate_text(self.verifier_id, "scientific domain verifier ID")
        _validate_sha256(self.trust_root_id, "scientific domain trust-root ID")
        if (
            isinstance(self.ledger_event_index, bool)
            or not isinstance(self.ledger_event_index, int)
            or self.ledger_event_index < 0
        ):
            raise DomainInputError("scientific domain plan event index is invalid")


@dataclass(frozen=True, slots=True)
class ScientificDomainAdmissionResolution:
    """Read-only availability/result for one production domain admission."""

    status: ScientificDomainAdmissionStatus
    reason_code: str
    reason: str
    plan_artifact_sha256: str | None = None
    source_artifact_sha256: str | None = None
    evidence: object | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ScientificDomainAdmissionStatus):
            raise DomainInputError("scientific domain admission status must be typed")
        _validate_text(self.reason_code, "scientific domain admission reason code")
        _validate_text(self.reason, "scientific domain admission reason")
        _validate_optional_sha256(
            self.plan_artifact_sha256,
            "scientific domain admission plan",
        )
        _validate_optional_sha256(
            self.source_artifact_sha256,
            "scientific domain admission source",
        )
        if self.status is ScientificDomainAdmissionStatus.VERIFIED:
            if (
                self.plan_artifact_sha256 is None
                or self.source_artifact_sha256 is None
                or self.evidence is None
            ):
                raise DomainInputError(
                    "verified scientific domain admission lacks its source"
                )
        elif self.source_artifact_sha256 is not None or self.evidence is not None:
            raise DomainInputError(
                "unavailable scientific domain admission cannot carry authority"
            )


@dataclass(frozen=True, slots=True)
class _ScientificDomainSourceProfile:
    domain: DomainKind
    source_format_id: str
    source_format_version: str
    attestation_schema: str
    verifier_id: str
    domain_separator: str
    unavailable_status: ScientificDomainAdmissionStatus
    reason_code: str
    reason: str

    @property
    def key(self) -> tuple[DomainKind, str, str]:
        return self.domain, self.source_format_id, self.source_format_version


@dataclass(frozen=True, slots=True)
class _ScientificDomainSourceCandidate:
    plan: ScientificDomainEvidencePlan
    plan_record: ArtifactRecord
    raw_source_record: ArtifactRecord
    raw_source_payload: Mapping[str, object]
    canonical_run_record: ArtifactRecord
    canonical_run_binding: object
    scientific_execution_authority_record: ArtifactRecord
    scientific_execution_authority: object


@dataclass(frozen=True, slots=True)
class _ScientificDomainVerifiedEvidence:
    evidence: object
    semantic_source_records: tuple[ArtifactRecord, ...]


_ScientificDomainSourceVerifier = Callable[
    [ArtifactRegistry, EventLedger, _ScientificDomainSourceCandidate],
    _ScientificDomainVerifiedEvidence,
]


_SCIENTIFIC_DOMAIN_SOURCE_PROFILES: Mapping[
    tuple[DomainKind, str, str], _ScientificDomainSourceProfile
] = MappingProxyType(
    {
        (
            DomainKind.GENERIC_ML,
            SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID,
            SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
        ): _ScientificDomainSourceProfile(
            domain=DomainKind.GENERIC_ML,
            source_format_id=SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID,
            source_format_version=(
                SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION
            ),
            attestation_schema=SCIENTIFIC_DOMAIN_GENERIC_ML_ATTESTATION_SCHEMA,
            verifier_id=SCIENTIFIC_DOMAIN_GENERIC_ML_VERIFIER_ID,
            domain_separator=(
                "SCIENTIST_ONE_TRUSTED_KERNEL_GENERIC_ML_OBSERVATIONS_V1"
            ),
            unavailable_status=(
                ScientificDomainAdmissionStatus.BLOCKED_EXTERNAL
            ),
            reason_code="GENERIC_ML_OBSERVATION_TRUST_ROOT_UNAVAILABLE",
            reason=(
                "the trusted-kernel Generic-ML observation format requires "
                "an externally provisioned local trust root with unique bytes "
                "for this run registry"
            ),
        ),
        (
            DomainKind.GENERIC_ML,
            SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID,
            GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
        ): _ScientificDomainSourceProfile(
            domain=DomainKind.GENERIC_ML,
            source_format_id=SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID,
            source_format_version=GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
            attestation_schema=GENERIC_ML_ATTESTATION_SCHEMA,
            verifier_id=GENERIC_ML_VERIFIER_ID,
            domain_separator=GENERIC_ML_ATTESTATION_DOMAIN_SEPARATOR,
            unavailable_status=ScientificDomainAdmissionStatus.BLOCKED_EXTERNAL,
            reason_code="GENERIC_ML_OBSERVATION_TRUST_ROOT_UNAVAILABLE",
            reason=(
                "the trusted-kernel Generic-ML observation format requires "
                "an externally provisioned local trust root with unique bytes "
                "for this run registry"
            ),
        ),
    }
)


def _read_generic_ml_observation_trust_root(
    registry: ArtifactRegistry,
) -> bytes | None:
    """Read, but never create, one unique-per-run local HMAC root.

    Cross-run non-reuse is an external provisioning requirement: this
    run-scoped reader has no project-global keyring and cannot prove it.
    """

    if type(registry) is not ArtifactRegistry:
        raise DomainInputError(
            "Generic-ML trust-root access requires exact ArtifactRegistry"
        )
    relative = (
        registry.base_path
        / SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME
    )
    try:
        directory_fd = open_confined_directory_fd(
            registry.policy.root,
            relative.parent,
            create=False,
        )
    except Exception as exc:
        raise ScientificDomainAdmissionUnavailable(
            ScientificDomainAdmissionStatus.BLOCKED_LOCAL,
            "GENERIC_ML_TRUST_ROOT_NAMESPACE_UNSAFE",
            "the Generic-ML trust-root namespace cannot be safely opened",
        ) from exc
    descriptor: int | None = None
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(
                relative.name,
                flags,
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return None
        metadata = os.fstat(descriptor)
        named = os.stat(
            relative.name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_mode & 0o777) != 0o600
            or metadata.st_size
            != _SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BYTES
            or identity != (named.st_dev, named.st_ino)
        ):
            raise ScientificDomainAdmissionUnavailable(
                ScientificDomainAdmissionStatus.BLOCKED_LOCAL,
                "GENERIC_ML_TRUST_ROOT_UNSAFE",
                "the Generic-ML local trust root is unsafe",
            )
        value = os.read(
            descriptor,
            _SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BYTES + 1,
        )
        final = os.fstat(descriptor)
        final_named = os.stat(
            relative.name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            len(value) != _SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BYTES
            or (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
            != (
                final.st_dev,
                final.st_ino,
                final.st_mode,
                final.st_nlink,
                final.st_size,
                final.st_mtime_ns,
                final.st_ctime_ns,
            )
            or identity != (final_named.st_dev, final_named.st_ino)
        ):
            raise ScientificDomainAdmissionUnavailable(
                ScientificDomainAdmissionStatus.BLOCKED_LOCAL,
                "GENERIC_ML_TRUST_ROOT_CHANGED",
                "the Generic-ML local trust root changed during read",
            )
        return value
    except ScientificDomainAdmissionUnavailable:
        raise
    except OSError as exc:
        raise ScientificDomainAdmissionUnavailable(
            ScientificDomainAdmissionStatus.BLOCKED_LOCAL,
            "GENERIC_ML_TRUST_ROOT_READ_FAILED",
            "the Generic-ML local trust root cannot be safely read",
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def _require_generic_ml_observation_trust_root(
    registry: ArtifactRegistry,
    *,
    expected_trust_root_id: str | None,
    _reader: Callable[[ArtifactRegistry], bytes | None] = (
        _read_generic_ml_observation_trust_root
    ),
) -> tuple[bytes, str]:
    key = _reader(registry)
    if key is None:
        if expected_trust_root_id is None:
            raise ScientificDomainAdmissionUnavailable(
                ScientificDomainAdmissionStatus.BLOCKED_EXTERNAL,
                "GENERIC_ML_OBSERVATION_TRUST_ROOT_UNAVAILABLE",
                "the externally provisioned Generic-ML local trust root is unavailable",
            )
        raise DomainInputError(
            "the prospectively pinned Generic-ML trust root is unavailable"
        )
    trust_root_id = sha256_bytes(key)
    if (
        expected_trust_root_id is not None
        and trust_root_id != expected_trust_root_id
    ):
        raise DomainInputError(
            "Generic-ML trust-root replacement or rotation invalidates the plan"
        )
    return key, trust_root_id


_SCIENTIFIC_DOMAIN_TRUST_ROOT_READERS = MappingProxyType(
    {
        (
            DomainKind.GENERIC_ML,
            SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID,
            SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
        ): _require_generic_ml_observation_trust_root,
    }
)


def _require_scientific_domain_profile_trust_root(
    registry: ArtifactRegistry,
    profile: _ScientificDomainSourceProfile,
    *,
    expected_trust_root_id: str | None,
    _readers: Mapping[
        tuple[DomainKind, str, str], Callable[..., tuple[bytes, str]]
    ] = _SCIENTIFIC_DOMAIN_TRUST_ROOT_READERS,
) -> tuple[bytes, str]:
    reader = _readers.get(profile.key)
    if reader is None:
        raise ScientificDomainAdmissionUnavailable(
            ScientificDomainAdmissionStatus.UNSUPPORTED,
            "SCIENTIFIC_DOMAIN_TRUST_PROFILE_UNSUPPORTED",
            "the source profile has no source-owned trust-root reader",
        )
    return reader(
        registry,
        expected_trust_root_id=expected_trust_root_id,
    )


def _validate_hash_tuple(
    values: tuple[str, ...], label: str, *, maximum: int = 256
) -> None:
    if (
        not isinstance(values, tuple)
        or not values
        or len(values) > maximum
    ):
        raise DomainInputError(f"{label} must be a non-empty unique bounded tuple")
    for value in values:
        _validate_sha256(value, label)
    if len(set(values)) != len(values):
        raise DomainInputError(f"{label} must be a non-empty unique bounded tuple")


def _scientific_domain_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise DomainInputError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DomainInputError(f"{label} must be a UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise DomainInputError(f"{label} must be a UTC timestamp")
    return parsed


def _require_scientific_domain_causal_time(
    *,
    earlier: object,
    earlier_label: str,
    later: object,
    later_label: str,
    failure: str,
) -> None:
    """Require one authoritative registry/ledger timestamp edge."""

    if _scientific_domain_timestamp(later, later_label) < (
        _scientific_domain_timestamp(earlier, earlier_label)
    ):
        raise DomainInputError(failure)


def _require_scientific_domain_runtime(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
) -> tuple[RegistryValidationResult, LedgerValidationResult]:
    """Verify the exact run-scoped registry/ledger pair before admission."""

    if type(registry) is not ArtifactRegistry or type(ledger) is not EventLedger:
        raise DomainInputError(
            "scientific domain admission requires exact ArtifactRegistry and EventLedger"
        )
    validate_identifier(run_id, "scientific domain ledger run ID")
    if (
        registry.policy.root != ledger.policy.root
        or registry.base_path.name != "registry"
        or ledger.relative_path.name != "events.jsonl"
        or registry.base_path.parent != ledger.relative_path.parent
    ):
        raise DomainInputError(
            "scientific domain admission requires the canonical paired registry and ledger"
        )
    try:
        registry_result = registry.verify_all(raise_on_error=True)
        ledger_result = ledger.validate(raise_on_error=True)
    except (ArtifactError, LedgerError, ValidationError) as exc:
        raise DomainInputError(
            "scientific domain registry or ledger failed verification"
        ) from exc
    if not ledger_result.events:
        raise DomainInputError(
            "scientific domain admission requires an initialized ledger"
        )
    if any(event.run_id != run_id for event in ledger_result.events):
        raise DomainInputError("scientific domain ledger names another run")
    return registry_result, ledger_result


def _scientific_domain_artifact_plan(
    registry: ArtifactRegistry,
    payload: Mapping[str, object],
    *,
    logical_type: str,
    origin: str,
    creator_role: Role,
    creation_command: tuple[str, ...],
    parent_artifacts: tuple[str, ...],
    schema_version: str,
    created_at: str,
) -> tuple[bytes, ArtifactRecord]:
    data = canonical_json_bytes(payload) + b"\n"
    digest = sha256_bytes(data)
    object_path = registry.objects_path / digest[:2] / digest
    metadata_path = registry.metadata_path / digest[:2] / f"{digest}.json"
    return data, ArtifactRecord(
        sha256=digest,
        path=object_path.as_posix(),
        relative_path=object_path.as_posix(),
        metadata_path=metadata_path.as_posix(),
        logical_type=logical_type,
        schema_version=schema_version,
        mime_type="application/json",
        size=len(data),
        origin=origin,
        creator_role=creator_role,
        creation_command=creation_command,
        parent_artifacts=parent_artifacts,
        validation_result="PASS",
        frozen=True,
        created_at=created_at,
    )


def _preflight_scientific_domain_publication(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    plans: tuple[tuple[bytes, ArtifactRecord], ...],
    event_id: str,
    event_timestamp: str,
    actor_role: Role,
    event_artifact_hashes: tuple[str, ...],
    reason: str,
    metadata: Mapping[str, object],
    dataset_identifiers: tuple[str, ...] = (),
    random_seeds: tuple[int, ...] = (),
) -> tuple[
    RegistryValidationResult,
    LedgerValidationResult,
    frozenset[str],
    LedgerEvent | None,
]:
    """Preflight an append-only registry-first/ledger-second publication."""

    registry_result, ledger_result = _require_scientific_domain_runtime(
        registry,
        ledger,
        run_id=run_id,
    )
    expected_by_hash = {record.sha256: (data, record) for data, record in plans}
    if len(expected_by_hash) != len(plans) or not plans:
        raise DomainInputError(
            "scientific domain publication artifacts must be non-empty and unique"
        )
    if tuple(expected_by_hash) != tuple(record.sha256 for _data, record in plans):
        raise DomainInputError("scientific domain publication order is ambiguous")
    if event_artifact_hashes != tuple(record.sha256 for _data, record in plans):
        raise DomainInputError(
            "scientific domain event must bind the exact publication order"
        )
    current_records = {record.sha256: record for record in registry_result.records}
    missing: set[str] = set()
    for digest, (data, expected) in expected_by_hash.items():
        existing = current_records.get(digest)
        if existing is None:
            missing.add(digest)
        elif existing != expected or registry.get_bytes(digest) != data:
            raise DomainInputError("scientific domain publication artifact collides")
    matches = tuple(
        (index, event)
        for index, event in enumerate(ledger_result.events)
        if event.event_id == event_id
    )
    if len(matches) > 1:
        raise DomainInputError("scientific domain publication event is ambiguous")
    event_to_append: LedgerEvent | None = None
    if matches:
        event_index, existing_event = matches[0]
        if missing or event_index == 0:
            raise DomainInputError(
                "scientific domain publication event precedes its artifacts"
            )
        prior = ledger_result.events[event_index - 1]
        expected_event = LedgerEvent.create(
            run_id=run_id,
            actor_role=actor_role,
            state_before=prior.requested_state_after,
            requested_state_after=prior.requested_state_after,
            artifact_hashes=event_artifact_hashes,
            code_version=prior.code_version,
            configuration_hash=prior.configuration_hash,
            dataset_identifiers=dataset_identifiers,
            random_seeds=random_seeds,
            reason=reason,
            prior_event_hash=prior.event_hash,
            event_id=event_id,
            timestamp=event_timestamp,
            event_type="CHECKPOINT",
            metadata=metadata,
        )
        if existing_event != expected_event or any(
            later.event_type == "CORRECTION"
            and later.supersedes_event_id == existing_event.event_id
            for later in ledger_result.events[event_index + 1 :]
        ):
            raise DomainInputError(
                "scientific domain publication event is substituted or corrected"
            )
    else:
        expected_artifacts = set(event_artifact_hashes)
        if any(
            expected_artifacts.intersection(event.artifact_hashes)
            for event in ledger_result.events
        ):
            raise DomainInputError(
                "scientific domain publication artifacts name another event"
            )
        current = ledger_result.events[-1]
        event_to_append = LedgerEvent.create(
            run_id=run_id,
            actor_role=actor_role,
            state_before=current.requested_state_after,
            requested_state_after=current.requested_state_after,
            artifact_hashes=event_artifact_hashes,
            code_version=current.code_version,
            configuration_hash=current.configuration_hash,
            dataset_identifiers=dataset_identifiers,
            random_seeds=random_seeds,
            reason=reason,
            prior_event_hash=current.event_hash,
            event_id=event_id,
            timestamp=event_timestamp,
            event_type="CHECKPOINT",
            metadata=metadata,
        )
    if len(current_records) + len(missing) > MAX_REGISTRY_RECORDS:
        raise DomainInputError(
            "scientific domain publication exceeds registry capacity"
        )
    if event_to_append is not None:
        event_bytes = canonical_json_bytes(event_to_append.to_dict()) + b"\n"
        if len(ledger_result.events) + 1 > MAX_LEDGER_EVENTS:
            raise DomainInputError(
                "scientific domain publication exceeds ledger event capacity"
            )
        if ledger_result.valid_prefix_bytes + len(event_bytes) > MAX_LEDGER_BYTES:
            raise DomainInputError(
                "scientific domain publication exceeds ledger byte capacity"
            )
    return registry_result, ledger_result, frozenset(missing), event_to_append


def _commit_scientific_domain_publication(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    plans: tuple[tuple[bytes, ArtifactRecord], ...],
    registry_snapshot: RegistryValidationResult,
    ledger_snapshot: LedgerValidationResult,
    missing: frozenset[str],
    event_to_append: LedgerEvent | None,
) -> tuple[ArtifactRecord, ...]:
    """Commit under paired locks; an exact registry orphan is retryable."""

    committed: list[ArtifactRecord] = []
    registry_guard = registry._open_mutation_lock()
    try:
        ledger_guard = ledger._open_lock()
        try:
            locked_registry = registry._verify_all_locked(
                registry_guard,
                raise_on_error=True,
            )
            locked_ledger_bytes = ledger._read_raw_locked(ledger_guard)
            locked_ledger = ledger._validate_bytes(locked_ledger_bytes)
            if (
                not locked_ledger.valid
                or locked_registry != registry_snapshot
                or locked_ledger != ledger_snapshot
            ):
                raise DomainInputError(
                    "scientific domain publication snapshots changed before commit"
                )
            for data, expected in plans:
                if expected.sha256 in missing:
                    actual = registry._put_bytes_locked(
                        registry_guard,
                        data,
                        logical_type=expected.logical_type,
                        origin=expected.origin,
                        creator_role=expected.creator_role,
                        creation_command=expected.creation_command,
                        parent_artifacts=expected.parent_artifacts,
                        schema_version=expected.schema_version,
                        mime_type=expected.mime_type,
                        validation_result=expected.validation_result,
                        frozen=expected.frozen,
                        created_at=expected.created_at,
                    )
                else:
                    actual = registry._get_metadata_locked(
                        registry_guard,
                        expected.sha256,
                    )
                if actual != expected:
                    raise DomainInputError(
                        "scientific domain publication changed during commit"
                    )
                committed.append(actual)
            if event_to_append is not None:

                def build_event(current: LedgerValidationResult) -> LedgerEvent:
                    if current != locked_ledger:
                        raise DomainInputError(
                            "scientific domain ledger changed during commit"
                        )
                    return event_to_append

                appended = ledger._append_locked(ledger_guard, build_event)
                if appended != event_to_append:
                    raise DomainInputError(
                        "scientific domain event changed during commit"
                    )
            registry._verify_mutation_namespace(registry_guard)
        finally:
            ledger._unlock(ledger_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    return tuple(committed)


def resolve_scientific_domain_admission_profile(
    *,
    domain: DomainKind,
    source_format_id: str,
    source_format_version: str,
    registry: ArtifactRegistry | None = None,
) -> ScientificDomainAdmissionResolution:
    """Report a production profile boundary without granting authority."""

    if not isinstance(domain, DomainKind):
        raise DomainInputError("scientific domain profile requires a typed domain")
    if (
        not isinstance(source_format_id, str)
        or not _RAW_SOURCE_ID_RE.fullmatch(source_format_id)
    ):
        raise DomainInputError("scientific domain source-format ID is invalid")
    _validate_text(source_format_version, "scientific domain source-format version")
    profile = _SCIENTIFIC_DOMAIN_SOURCE_PROFILES.get(
        (domain, source_format_id, source_format_version)
    )
    if profile is None:
        return ScientificDomainAdmissionResolution(
            status=ScientificDomainAdmissionStatus.UNSUPPORTED,
            reason_code="SCIENTIFIC_DOMAIN_SOURCE_FORMAT_UNSUPPORTED",
            reason=(
                "no reviewed source-owned admission policy exists for this "
                "domain and raw-source format"
            ),
        )
    if registry is not None:
        try:
            _require_scientific_domain_profile_trust_root(
                registry,
                profile,
                expected_trust_root_id=None,
            )
        except ScientificDomainAdmissionUnavailable as exc:
            return ScientificDomainAdmissionResolution(
                status=exc.status,
                reason_code=exc.reason_code,
                reason=exc.reason,
            )
    return ScientificDomainAdmissionResolution(
        status=ScientificDomainAdmissionStatus.BLOCKED_LOCAL,
        reason_code="SCIENTIFIC_DOMAIN_SOURCE_REQUIRES_BOUND_CANDIDATE",
        reason=(
            "the source profile is implemented but no exact plan, run, and raw "
            "source candidate was supplied"
        ),
    )


def _domain_slug(domain: DomainKind) -> str:
    return domain.value.lower()


def _source_logical_type(domain: DomainKind) -> str:
    return f"domain_evidence_source.{_domain_slug(domain)}"


def _raw_source_logical_type(domain: DomainKind, source_id: str) -> str:
    return f"domain_raw_fixture.{_domain_slug(domain)}.{source_id}"


def _manifest_logical_type(domain: DomainKind) -> str:
    return f"domain_evidence_manifest.{_domain_slug(domain)}"


def _receipt_logical_type(domain: DomainKind) -> str:
    # Keep the established prefix consumed by soundness/challenger policy while
    # replacing value-only labels with a receipt that must be freshly replayed.
    return f"domain_validity.{_domain_slug(domain)}"


def _source_origin(domain: DomainKind, object_id: str) -> str:
    return (
        f"non-evidentiary registry-bound {domain.value} evidence source "
        f"for {object_id}"
    )


def _raw_source_origin(
    domain: DomainKind, object_id: str, source_id: str
) -> str:
    return (
        f"typed non-evidentiary {domain.value} raw source {source_id} "
        f"for {object_id}"
    )


def _manifest_origin(domain: DomainKind, object_id: str) -> str:
    return f"registry-bound {domain.value} evidence manifest for {object_id}"


def _receipt_origin(domain: DomainKind, object_id: str) -> str:
    return f"deterministically replayed {domain.value} validity receipt for {object_id}"


def _fixture_limitations(
    domain: DomainKind,
) -> tuple[DomainValidityLimitation, ...]:
    limitations = [
        DomainValidityLimitation.NON_EVIDENTIARY_FIXTURE,
        DomainValidityLimitation.REAL_WORKLOAD_UNTESTED,
        DomainValidityLimitation.SCIENTIFIC_PROMOTION_PROHIBITED,
        DomainValidityLimitation.EXTERNAL_VALIDATION_UNTESTED,
    ]
    if domain is DomainKind.MEDICAL_IMAGING:
        limitations.append(DomainValidityLimitation.CLINICAL_VALIDATION_UNTESTED)
    return tuple(limitations)


def _domain_evidence_type(domain: DomainKind) -> type:
    mapping: dict[DomainKind, type] = {
        DomainKind.GENERIC_ML: GenericMLValidityEvidence,
        DomainKind.MEDICAL_IMAGING: MedicalImagingValidityEvidence,
        DomainKind.TIME_SERIES: TimeSeriesValidityEvidence,
        DomainKind.RECOMMENDER_SYSTEMS: RecommenderValidityEvidence,
        DomainKind.OPERATIONS_RESEARCH: OperationsResearchValidityEvidence,
        DomainKind.SYSTEMS: SystemsValidityEvidence,
    }
    try:
        return mapping[domain]
    except (KeyError, TypeError) as exc:
        raise DomainInputError("domain evidence kind is unsupported") from exc


def _domain_record_types() -> dict[str, type]:
    values = (
        GenericMLExample,
        EarlyStoppingPolicyEvidence,
        AugmentationPolicyEvidence,
        ModelResourceComparisonEvidence,
        PretrainedResourceEvidence,
        PretrainedResourcePolicyEvidence,
        GenericMLValidityEvidence,
        GenericMLFixedModelValidityEvidence,
        GenericMLReferenceWorkPolicy,
        GenericMLReferenceWork,
        MedicalImageObservation,
        MedicalClassificationSemantics,
        MedicalSegmentationSemantics,
        MedicalRegistrationSemantics,
        MedicalClinicalInterpretationEvidence,
        MedicalImagingValidityEvidence,
        TimeSeriesWindow,
        TimeSeriesValidityEvidence,
        RecommenderInteraction,
        RecommenderValidityEvidence,
        OptimizationInstanceResult,
        OperationsResearchValidityEvidence,
        SystemsMeasurement,
        SystemsValidityEvidence,
    )
    return {value.__name__: value for value in values}


def _domain_enum_types() -> dict[str, type[StrEnum]]:
    values: tuple[type[StrEnum], ...] = (
        SplitRole,
        MLPolicyTiming,
        AugmentationMode,
        ComparisonDisposition,
        PretrainedContaminationStatus,
        MedicalTask,
        MedicalAnalysisUnit,
        MedicalImageRepresentation,
        MedicalClassificationTarget,
        MedicalSegmentationTarget,
        MedicalRegistrationTransform,
        MedicalRegistrationReference,
        MedicalMetric,
        MedicalClinicalUse,
        MedicalThresholdBasis,
        MedicalThresholdUnit,
        MedicalThresholdRelation,
        RecommenderSplitStrategy,
        ObjectiveDirection,
        MetricDirection,
        MetricScope,
        SystemsClaimScope,
    )
    return {value.__name__: value for value in values}


def _encode_domain_value(value: object) -> object:
    if isinstance(value, StrEnum):
        return {
            "kind": "enum",
            "type": type(value).__name__,
            "value": value.value,
        }
    if is_dataclass(value) and not isinstance(value, type):
        return {
            "kind": "record",
            "type": type(value).__name__,
            "fields": {
                item.name: _encode_domain_value(getattr(value, item.name))
                for item in fields(value)
            },
        }
    if isinstance(value, tuple):
        return {
            "kind": "tuple",
            "items": [_encode_domain_value(item) for item in value],
        }
    if value is None:
        return {"kind": "scalar", "type": "none"}
    if isinstance(value, bool):
        return {"kind": "scalar", "type": "bool", "value": value}
    if isinstance(value, int):
        return {"kind": "scalar", "type": "int", "value": value}
    if isinstance(value, float):
        if not math.isfinite(value):
            raise DomainInputError("domain evidence cannot contain non-finite values")
        return {"kind": "scalar", "type": "float", "value": value}
    if isinstance(value, str):
        return {"kind": "scalar", "type": "str", "value": value}
    raise DomainInputError(
        f"domain evidence contains unsupported type {type(value).__name__}"
    )


def _decode_domain_value(value: object) -> object:
    if not isinstance(value, Mapping) or not isinstance(value.get("kind"), str):
        raise DomainInputError("typed domain evidence node is malformed")
    kind = value["kind"]
    if kind == "scalar":
        scalar_type = value.get("type")
        if scalar_type == "none":
            if set(value) != {"kind", "type"}:
                raise DomainInputError("typed null domain value is malformed")
            return None
        if set(value) != {"kind", "type", "value"}:
            raise DomainInputError("typed scalar domain value is malformed")
        scalar = value["value"]
        valid = (
            (scalar_type == "bool" and isinstance(scalar, bool))
            or (
                scalar_type == "int"
                and isinstance(scalar, int)
                and not isinstance(scalar, bool)
            )
            or (scalar_type == "float" and isinstance(scalar, float))
            or (scalar_type == "str" and isinstance(scalar, str))
        )
        if not valid or (
            scalar_type == "float" and not math.isfinite(float(scalar))
        ):
            raise DomainInputError("typed scalar domain value has the wrong type")
        return scalar
    if kind == "tuple":
        if set(value) != {"kind", "items"} or not isinstance(value["items"], list):
            raise DomainInputError("typed tuple domain value is malformed")
        if len(value["items"]) > MAX_DOMAIN_RECORDS:
            raise DomainInputError("typed tuple domain value exceeds the record limit")
        return tuple(_decode_domain_value(item) for item in value["items"])
    if kind == "enum":
        if (
            set(value) != {"kind", "type", "value"}
            or not isinstance(value["type"], str)
            or not isinstance(value["value"], str)
        ):
            raise DomainInputError("typed enum domain value is malformed")
        enum_type = _domain_enum_types().get(value["type"])
        if enum_type is None:
            raise DomainInputError("typed domain evidence names an unknown enum")
        try:
            return enum_type(value["value"])
        except ValueError as exc:
            raise DomainInputError("typed domain evidence enum value is unknown") from exc
    if kind == "record":
        if (
            set(value) != {"kind", "type", "fields"}
            or not isinstance(value["type"], str)
            or not isinstance(value["fields"], Mapping)
        ):
            raise DomainInputError("typed record domain value is malformed")
        record_type = _domain_record_types().get(value["type"])
        if record_type is None:
            raise DomainInputError("typed domain evidence names an unknown record")
        expected_fields = tuple(item.name for item in fields(record_type))
        if set(value["fields"]) != set(expected_fields):
            raise DomainInputError("typed domain evidence record fields are incomplete")
        decoded = {
            name: _decode_domain_value(value["fields"][name])
            for name in expected_fields
        }
        try:
            return record_type(**decoded)
        except (TypeError, ValueError, ValidationError) as exc:
            raise DomainInputError("typed domain evidence record is invalid") from exc
    raise DomainInputError("typed domain evidence node kind is unknown")


def _embedded_artifact_hashes(value: object) -> tuple[str, ...]:
    hashes: list[str] = []

    def visit(current: object, field_name: str | None = None) -> None:
        if isinstance(current, StrEnum):
            return
        if is_dataclass(current) and not isinstance(current, type):
            for item in fields(current):
                visit(getattr(current, item.name), item.name)
            return
        if isinstance(current, tuple):
            for item in current:
                visit(item)
            return
        if (
            field_name is not None
            and field_name.endswith("_sha256")
            and isinstance(current, str)
        ):
            _validate_sha256(current, f"embedded {field_name}")
            if current not in hashes:
                hashes.append(current)

    visit(value)
    return tuple(hashes)


def _artifact_descriptor(record: ArtifactRecord) -> dict[str, object]:
    return {
        "artifact_sha256": record.sha256,
        "logical_type": record.logical_type,
        "schema_version": record.schema_version,
        "mime_type": record.mime_type,
        "origin": record.origin,
        "creator_role": record.creator_role.value,
        "creation_command": list(record.creation_command),
        "parent_artifacts": list(record.parent_artifacts),
        "validation_result": record.validation_result,
        "frozen": record.frozen,
    }


def _canonical_registry_object(
    registry: ArtifactRegistry,
    artifact_sha256: str,
    label: str,
) -> tuple[ArtifactRecord, Mapping[str, object]]:
    _validate_sha256(artifact_sha256, f"{label} SHA-256")
    try:
        registry.verify(artifact_sha256, raise_on_error=True)
        record = registry.get_metadata(artifact_sha256)
        raw = registry.get_bytes(artifact_sha256)
        value = safe_json_loads(raw)
    except (ArtifactError, UnsafeSerializationError, ValidationError) as exc:
        raise DomainInputError(f"{label} is absent, unsafe, or corrupt") from exc
    if not isinstance(value, Mapping):
        raise DomainInputError(f"{label} must be a canonical JSON object")
    if raw != canonical_json_bytes(value) + b"\n":
        raise DomainInputError(f"{label} is not canonical JSON")
    return record, value


def _scientific_domain_plan_logical_type(domain: DomainKind) -> str:
    return f"scientific_domain_evidence_plan.{_domain_slug(domain)}"


def _scientific_domain_plan_origin(domain: DomainKind, object_id: str) -> str:
    return (
        f"prospective {domain.value} domain-evidence policy for {object_id}"
    )


def _scientific_domain_plan_event_id(plan_artifact_sha256: str) -> str:
    _validate_sha256(plan_artifact_sha256, "scientific domain plan")
    return f"evt-domain-plan-{plan_artifact_sha256[:32]}"


def _scientific_domain_trust_revocation_event_id(trust_root_id: str) -> str:
    _validate_sha256(trust_root_id, "scientific domain trust-root ID")
    return f"evt-domain-root-revoked-{trust_root_id[:32]}"


def _scientific_domain_trust_revocation_metadata(
    plan: ScientificDomainEvidencePlan,
) -> Mapping[str, object]:
    return _scientific_domain_trust_revocation_metadata_values(
        plan_artifact_sha256=plan.plan_artifact_sha256,
        plan_record_hash=plan.plan_record_hash,
        domain=plan.domain,
        source_format_id=plan.source_format_id,
        source_format_version=plan.source_format_version,
        attestation_schema=plan.attestation_schema,
        verifier_id=plan.verifier_id,
        trust_root_id=plan.trust_root_id,
    )


def _scientific_domain_trust_revocation_metadata_values(
    *,
    plan_artifact_sha256: str,
    plan_record_hash: str,
    domain: DomainKind,
    source_format_id: str,
    source_format_version: str,
    attestation_schema: str,
    verifier_id: str,
    trust_root_id: str,
) -> Mapping[str, object]:
    return {
        "scientific_domain_trust_root_revocation": {
            "schema_version": (
                _SCIENTIFIC_DOMAIN_TRUST_REVOCATION_EVENT_SCHEMA
            ),
            "kind": "SCIENTIFIC_DOMAIN_TRUST_ROOT_IRREVERSIBLY_REVOKED",
            "plan_artifact_sha256": plan_artifact_sha256,
            "plan_record_hash": plan_record_hash,
            "domain": domain.value,
            "source_format_id": source_format_id,
            "source_format_version": source_format_version,
            "attestation_schema": attestation_schema,
            "verifier_id": verifier_id,
            "trust_root_id": trust_root_id,
            "irreversible": True,
            "authority_scope": "DENY_ONLY",
        }
    }


def _scientific_domain_trust_revocation_candidates(
    events: tuple[LedgerEvent, ...],
    *,
    trust_root_id: str,
    plan_artifact_sha256: str | None,
) -> tuple[tuple[int, LedgerEvent], ...]:
    event_id = _scientific_domain_trust_revocation_event_id(trust_root_id)
    matches: list[tuple[int, LedgerEvent]] = []
    for index, event in enumerate(events):
        metadata = thaw_json(event.metadata).get(
            "scientific_domain_trust_root_revocation"
        )
        if (
            event.event_id == event_id
            or (
                isinstance(metadata, Mapping)
                and (
                    metadata.get("trust_root_id") == trust_root_id
                    or (
                        plan_artifact_sha256 is not None
                        and metadata.get("plan_artifact_sha256")
                        == plan_artifact_sha256
                    )
                )
            )
        ):
            matches.append((index, event))
    return tuple(matches)


def _reject_revoked_scientific_domain_trust_root(
    events: tuple[LedgerEvent, ...],
    *,
    trust_root_id: str,
    plan_artifact_sha256: str | None,
) -> None:
    if _scientific_domain_trust_revocation_candidates(
        events,
        trust_root_id=trust_root_id,
        plan_artifact_sha256=plan_artifact_sha256,
    ):
        raise DomainInputError(
            "the scientific domain trust root is irreversibly revoked"
        )


def _scientific_domain_plan_event_metadata(
    value: Mapping[str, object],
    record: ArtifactRecord,
) -> Mapping[str, object]:
    return {
        "scientific_domain_evidence_plan": {
            "schema_version": _SCIENTIFIC_DOMAIN_PLAN_EVENT_SCHEMA,
            "kind": "SCIENTIFIC_DOMAIN_EVIDENCE_PLANNED",
            "plan_artifact_sha256": record.sha256,
            "plan_record_hash": str(record.record_hash),
            "plan": dict(value),
        }
    }


def _scientific_domain_profile(
    domain: DomainKind,
    source_format_id: str,
    source_format_version: str,
) -> _ScientificDomainSourceProfile:
    resolution = resolve_scientific_domain_admission_profile(
        domain=domain,
        source_format_id=source_format_id,
        source_format_version=source_format_version,
    )
    profile = _SCIENTIFIC_DOMAIN_SOURCE_PROFILES.get(
        (domain, source_format_id, source_format_version)
    )
    if profile is None:
        raise ScientificDomainAdmissionUnavailable(
            resolution.status,
            resolution.reason_code,
            resolution.reason,
        )
    return profile


def _generic_ml_checkpoint_selection_matches_profile(
    checkpoint_split_id: object,
    *,
    source_format_version: str,
    split_ids: set[str],
) -> bool:
    """Match the frozen policy without granting execution or validity facts."""

    if source_format_version == GENERIC_ML_OBSERVATIONS_FORMAT_VERSION:
        # V2 models are fixed before confirmation; no checkpoint may be
        # selected. None is not a missing training policy in this exact wire.
        return checkpoint_split_id is None
    if source_format_version == SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION:
        # Preserve the legacy training profile, where a missing split remains
        # incomplete. Its downstream adapter still decides leakage validity.
        return type(checkpoint_split_id) is str and checkpoint_split_id in split_ids
    return False


def _replay_scientific_domain_plan_sources(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    domain: DomainKind,
    object_id: str,
    task_id: str,
    source_format_id: str,
    source_format_version: str,
    evaluation_contract_artifact_sha256: str,
    dataset_authority_artifact_sha256: str,
    split_authority_artifact_sha256s: tuple[str, ...],
    frozen_run_spec_artifact_sha256: str,
) -> tuple[
    object,
    object,
    tuple[object, ...],
    object,
    tuple[ArtifactRecord, ...],
]:
    """Freshly replay every owner before deriving prospective plan bytes."""

    _scientific_domain_profile(
        domain,
        source_format_id,
        source_format_version,
    )
    if len(split_authority_artifact_sha256s) != 4:
        raise DomainInputError(
            "scientific domain plan requires four ordered split authorities"
        )
    _validate_hash_tuple(
        split_authority_artifact_sha256s,
        "scientific domain plan split authorities",
        maximum=4,
    )
    try:
        from .experiments import require_scientific_execution_run_spec
        from .research_state import (
            SplitRole as ResearchSplitRole,
            require_scientific_dataset_authority,
            require_scientific_dataset_split_authority,
            require_scientific_experiment_dataset_projection,
        )
        from .scientific_design import require_frozen_evaluation_contract

        contract = require_frozen_evaluation_contract(
            registry,
            contract_artifact_sha256=evaluation_contract_artifact_sha256,
        )
        contract_record = registry.get_metadata(
            evaluation_contract_artifact_sha256
        )
        dataset_authority = require_scientific_dataset_authority(
            registry,
            ledger,
            run_id=run_id,
            authority_artifact_hash=dataset_authority_artifact_sha256,
            expected_dataset_id=contract.dataset.dataset_id,
        )
        expected_splits = (
            (ResearchSplitRole.TRAIN, contract.dataset.train_split_id),
            (
                ResearchSplitRole.EXPLORATORY,
                contract.dataset.development_split_id,
            ),
            (
                ResearchSplitRole.VALIDATION,
                contract.dataset.validation_split_id,
            ),
            (
                ResearchSplitRole.CONFIRMATORY,
                contract.dataset.confirmatory_split_id,
            ),
        )
        split_authorities = tuple(
            require_scientific_dataset_split_authority(
                registry,
                ledger,
                run_id=run_id,
                split_authority_artifact_hash=digest,
                expected_split_id=split_id,
                expected_split_role=role,
            )
            for digest, (role, split_id) in zip(
                split_authority_artifact_sha256s,
                expected_splits,
                strict=True,
            )
        )
        spec = require_scientific_execution_run_spec(
            registry,
            frozen_run_spec_artifact_sha256=frozen_run_spec_artifact_sha256,
        )
        spec_record = registry.get_metadata(frozen_run_spec_artifact_sha256)
        projection_record = require_scientific_experiment_dataset_projection(
            registry,
            ledger,
            run_id=run_id,
            projection_artifact_hash=spec.data_sha256,
            expected_dataset_authority_artifact_hash=(
                dataset_authority_artifact_sha256
            ),
            expected_evaluation_contract_artifact_hash=(
                evaluation_contract_artifact_sha256
            ),
        )
    except ScientificDomainAdmissionUnavailable:
        raise
    except Exception as exc:
        raise DomainInputError(
            "scientific domain plan source authority failed fresh replay"
        ) from exc
    try:
        hypothesis = contract.hypothesis_register.hypothesis(spec.hypothesis_id)
    except Exception as exc:
        raise DomainInputError(
            "scientific domain run spec names no frozen-contract hypothesis"
        ) from exc
    required_ablations = tuple(
        item.ablation_id
        for item in contract.ablations
        if item.hypothesis_id == spec.hypothesis_id and item.required
    )
    spec_metadata = thaw_json(spec.metadata)
    domain_policy = spec_metadata.get("scientific_domain_policy")
    domain_policy_keys = {
        "schema_version",
        "domain",
        "source_format_id",
        "source_format_version",
        "preprocessing_fit_split_ids",
        "checkpoint_selection_split_id",
        "early_stopping",
        "augmentation",
        "metric_policy",
        "generalization_scope",
    }
    if source_format_version == GENERIC_ML_OBSERVATIONS_FORMAT_VERSION:
        domain_policy_keys.add("comparison_scope")
    split_ids = {
        contract.dataset.train_split_id,
        contract.dataset.development_split_id,
        contract.dataset.validation_split_id,
        contract.dataset.confirmatory_split_id,
    }
    expected_generic_ml_metric_policy_schema = (
        GENERIC_ML_POLICY_SCHEMA
        if source_format_version == GENERIC_ML_OBSERVATIONS_FORMAT_VERSION
        else _SCIENTIFIC_DOMAIN_GENERIC_ML_POLICY_SCHEMA
    )
    if (
        domain is DomainKind.GENERIC_ML
        and (
            not isinstance(domain_policy, Mapping)
            or set(domain_policy) != domain_policy_keys
            or domain_policy.get("schema_version")
            != "scientific-domain-policy/v1"
            or domain_policy.get("domain") != domain.value
            or domain_policy.get("source_format_id") != source_format_id
            or domain_policy.get("source_format_version")
            != source_format_version
            or domain_policy.get("generalization_scope")
            != "WITHIN_DATASET_ONLY"
            or (
                source_format_version == GENERIC_ML_OBSERVATIONS_FORMAT_VERSION
                and domain_policy.get("comparison_scope")
                != GENERIC_ML_COMPARISON_SCOPE
            )
            or not isinstance(
                domain_policy.get("preprocessing_fit_split_ids"), list
            )
            or any(
                item not in split_ids
                for item in domain_policy.get(
                    "preprocessing_fit_split_ids", []
                )
            )
            or not _generic_ml_checkpoint_selection_matches_profile(
                domain_policy.get("checkpoint_selection_split_id"),
                source_format_version=source_format_version,
                split_ids=split_ids,
            )
            or not isinstance(domain_policy.get("early_stopping"), Mapping)
            or set(domain_policy.get("early_stopping", {}))
            != {"enabled", "monitor_split_id"}
            or type(domain_policy["early_stopping"].get("enabled")) is not bool
            or domain_policy["early_stopping"].get("monitor_split_id")
            not in {*split_ids, None}
            or not isinstance(domain_policy.get("augmentation"), Mapping)
            or set(domain_policy.get("augmentation", {}))
            != {"mode", "fit_split_ids", "application_split_ids"}
            or domain_policy["augmentation"].get("mode")
            not in {item.value for item in AugmentationMode}
            or any(
                not isinstance(domain_policy["augmentation"].get(name), list)
                or any(
                    item not in split_ids
                    for item in domain_policy["augmentation"].get(name, [])
                )
                for name in ("fit_split_ids", "application_split_ids")
            )
            or domain_policy.get("metric_policy")
            != {
                "schema_version": expected_generic_ml_metric_policy_schema,
                "metric_id": contract.primary_metric.metric_id,
                "semantics": "EXACT_INTEGER_LABEL_MATCH",
                "aggregation": "MICRO_EXAMPLE_MEAN",
                "unit": "FRACTION",
                "direction": "HIGHER_IS_BETTER",
            }
            or contract.primary_metric.unit.value != "FRACTION"
            or contract.primary_metric.direction.value != "HIGHER_IS_BETTER"
            or contract.primary_metric.aggregation != "MICRO_EXAMPLE_MEAN"
        )
    ):
        raise DomainInputError(
            "scientific domain policy is not exactly frozen in the run spec"
        )
    if (
        task_id != spec.experiment_id
        or hypothesis.planned_experiment != spec.experiment_id
        or spec.seeds != contract.seed_reporting.seeds
        or spec.required_ablations != required_ablations
        or dataset_authority.evaluation_contract_artifact_hash
        != evaluation_contract_artifact_sha256
        or dataset_authority.dataset_id != contract.dataset.dataset_id
        or projection_record.sha256 != spec.data_sha256
        or any(
            split.dataset_authority_artifact_hash
            != dataset_authority_artifact_sha256
            or split.evaluation_contract_artifact_hash
            != evaluation_contract_artifact_sha256
            for split in split_authorities
        )
    ):
        raise DomainInputError(
            "scientific domain plan differs from its frozen task, policy, or Dataset"
        )
    records = (
        contract_record,
        registry.get_metadata(dataset_authority_artifact_sha256),
        *(registry.get_metadata(item) for item in split_authority_artifact_sha256s),
        spec_record,
    )
    if any(record.record_hash is None for record in records):
        raise DomainInputError("scientific domain plan source record is unhashed")
    return contract, dataset_authority, split_authorities, spec, records


def _scientific_domain_plan_payload(
    *,
    run_id: str,
    domain: DomainKind,
    object_id: str,
    task_id: str,
    source_format_id: str,
    source_format_version: str,
    records: tuple[ArtifactRecord, ...],
    execution_run_id: str,
    attestation_schema: str,
    verifier_id: str,
    trust_root_id: str,
) -> Mapping[str, object]:
    contract_record = records[0]
    dataset_record = records[1]
    split_records = records[2:6]
    spec_record = records[6]
    return {
        "schema_version": SCIENTIFIC_DOMAIN_EVIDENCE_PLAN_SCHEMA_VERSION,
        "run_id": run_id,
        "domain": domain.value,
        "object_id": object_id,
        "task_id": task_id,
        "source_format_id": source_format_id,
        "source_format_version": source_format_version,
        "attestation_schema": attestation_schema,
        "verifier_id": verifier_id,
        "trust_root_id": trust_root_id,
        "evaluation_contract_artifact_sha256": contract_record.sha256,
        "evaluation_contract_record_hash": str(contract_record.record_hash),
        "dataset_authority_artifact_sha256": dataset_record.sha256,
        "dataset_authority_record_hash": str(dataset_record.record_hash),
        "split_authority_artifact_sha256s": [
            record.sha256 for record in split_records
        ],
        "split_authority_record_hashes": [
            str(record.record_hash) for record in split_records
        ],
        "frozen_run_spec_artifact_sha256": spec_record.sha256,
        "frozen_run_spec_record_hash": str(spec_record.record_hash),
        "execution_run_id": execution_run_id,
        "authority_scope": "PROSPECTIVE_DOMAIN_POLICY_ONLY",
        "scientific_evidence": False,
    }


def _scientific_domain_plan_slot_records(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
    *,
    run_id: str,
    object_id: str,
    task_id: str,
) -> tuple[ArtifactRecord, ...]:
    matches: list[ArtifactRecord] = []
    for record in records:
        if not record.logical_type.startswith("scientific_domain_evidence_plan."):
            continue
        try:
            value = safe_json_loads(registry.get_bytes(record.sha256))
        except Exception as exc:
            raise DomainInputError(
                "scientific domain plan slot contains an unreadable artifact"
            ) from exc
        if (
            isinstance(value, Mapping)
            and value.get("run_id") == run_id
            and value.get("object_id") == object_id
            and value.get("task_id") == task_id
        ):
            matches.append(record)
    return tuple(matches)


def register_scientific_domain_evidence_plan(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    run_id: str,
    domain: DomainKind,
    object_id: str,
    task_id: str,
    source_format_id: str,
    source_format_version: str,
    evaluation_contract_artifact_sha256: str,
    dataset_authority_artifact_sha256: str,
    split_authority_artifact_sha256s: tuple[str, ...],
    frozen_run_spec_artifact_sha256: str,
) -> ScientificDomainEvidencePlan:
    """Freeze domain/source selection before the matching run is prepared."""

    validate_identifier(run_id, "scientific domain plan run ID")
    validate_identifier(object_id, "scientific domain plan object ID")
    validate_identifier(task_id, "scientific domain plan task ID")
    if not isinstance(domain, DomainKind):
        raise DomainInputError("scientific domain plan requires a typed domain")
    registry_result, ledger_result = _require_scientific_domain_runtime(
        registry,
        ledger,
        run_id=run_id,
    )
    profile = _scientific_domain_profile(
        domain,
        source_format_id,
        source_format_version,
    )
    _trust_key, trust_root_id = _require_scientific_domain_profile_trust_root(
        registry,
        profile,
        expected_trust_root_id=None,
    )
    _reject_revoked_scientific_domain_trust_root(
        ledger_result.events,
        trust_root_id=trust_root_id,
        plan_artifact_sha256=None,
    )
    _contract, dataset_authority, _splits, spec, records = (
        _replay_scientific_domain_plan_sources(
            registry,
            ledger,
            run_id=run_id,
            domain=domain,
            object_id=object_id,
            task_id=task_id,
            source_format_id=source_format_id,
            source_format_version=source_format_version,
            evaluation_contract_artifact_sha256=(
                evaluation_contract_artifact_sha256
            ),
            dataset_authority_artifact_sha256=(
                dataset_authority_artifact_sha256
            ),
            split_authority_artifact_sha256s=(
                split_authority_artifact_sha256s
            ),
            frozen_run_spec_artifact_sha256=(
                frozen_run_spec_artifact_sha256
            ),
        )
    )
    payload = _scientific_domain_plan_payload(
        run_id=run_id,
        domain=domain,
        object_id=object_id,
        task_id=task_id,
        source_format_id=source_format_id,
        source_format_version=source_format_version,
        records=records,
        execution_run_id=spec.run_id,
        attestation_schema=profile.attestation_schema,
        verifier_id=profile.verifier_id,
        trust_root_id=trust_root_id,
    )
    slot_records = _scientific_domain_plan_slot_records(
        registry,
        registry_result.records,
        run_id=run_id,
        object_id=object_id,
        task_id=task_id,
    )
    if len(slot_records) > 1:
        raise DomainInputError("scientific domain plan slot is ambiguous")
    created_at = slot_records[0].created_at if slot_records else utc_now()
    artifact_plan = _scientific_domain_artifact_plan(
        registry,
        payload,
        logical_type=_scientific_domain_plan_logical_type(domain),
        origin=_scientific_domain_plan_origin(domain, object_id),
        creator_role=Role.PROTOCOL_DESIGNER,
        creation_command=_SCIENTIFIC_DOMAIN_PLAN_COMMAND,
        parent_artifacts=tuple(record.sha256 for record in records),
        schema_version=SCIENTIFIC_DOMAIN_EVIDENCE_PLAN_ARTIFACT_SCHEMA_VERSION,
        created_at=created_at,
    )
    if slot_records and slot_records != (artifact_plan[1],):
        raise DomainInputError(
            "scientific domain plan slot already binds another policy"
        )
    matching_preparations = tuple(
        event
        for event in ledger_result.events
        if isinstance(
            thaw_json(event.metadata).get("scientific_execution_preparation"),
            Mapping,
        )
        and thaw_json(event.metadata)["scientific_execution_preparation"].get(
            "frozen_run_spec_artifact_sha256"
        )
        == frozen_run_spec_artifact_sha256
    )
    event_id = _scientific_domain_plan_event_id(artifact_plan[1].sha256)
    existing_plan_event = any(
        event.event_id == event_id for event in ledger_result.events
    )
    if matching_preparations and not existing_plan_event:
        raise DomainInputError(
            "scientific domain policy cannot be selected after run preparation"
        )
    metadata = _scientific_domain_plan_event_metadata(payload, artifact_plan[1])
    (
        registry_snapshot,
        ledger_snapshot,
        missing,
        event_to_append,
    ) = _preflight_scientific_domain_publication(
        registry,
        ledger,
        run_id=run_id,
        plans=(artifact_plan,),
        event_id=event_id,
        event_timestamp=created_at,
        actor_role=Role.PROTOCOL_DESIGNER,
        event_artifact_hashes=(artifact_plan[1].sha256,),
        reason=(
            "froze domain, task, evaluation, Dataset, split, and source-format "
            "policy before scientific execution preparation"
        ),
        metadata=metadata,
        dataset_identifiers=(dataset_authority.dataset_id,),
        random_seeds=spec.seeds,
    )
    _commit_scientific_domain_publication(
        registry,
        ledger,
        plans=(artifact_plan,),
        registry_snapshot=registry_snapshot,
        ledger_snapshot=ledger_snapshot,
        missing=missing,
        event_to_append=event_to_append,
    )
    return require_scientific_domain_evidence_plan(
        registry,
        ledger,
        plan_artifact_sha256=artifact_plan[1].sha256,
        expected_run_id=run_id,
        expected_domain=domain,
        expected_object_id=object_id,
        expected_task_id=task_id,
    )


def _require_scientific_domain_evidence_plan(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    plan_artifact_sha256: str,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
    enforce_trust_root: bool,
    enforce_not_revoked: bool,
) -> ScientificDomainEvidencePlan:
    """Freshly replay one prospective domain plan and temporal ordering."""

    validate_identifier(expected_run_id, "expected scientific domain run ID")
    validate_identifier(expected_object_id, "expected scientific domain object ID")
    validate_identifier(expected_task_id, "expected scientific domain task ID")
    if not isinstance(expected_domain, DomainKind):
        raise DomainInputError("expected scientific domain must be typed")
    registry_result, ledger_result = _require_scientific_domain_runtime(
        registry,
        ledger,
        run_id=expected_run_id,
    )
    record, value = _canonical_registry_object(
        registry,
        plan_artifact_sha256,
        "scientific domain evidence plan",
    )
    required = {
        "schema_version",
        "run_id",
        "domain",
        "object_id",
        "task_id",
        "source_format_id",
        "source_format_version",
        "attestation_schema",
        "verifier_id",
        "trust_root_id",
        "evaluation_contract_artifact_sha256",
        "evaluation_contract_record_hash",
        "dataset_authority_artifact_sha256",
        "dataset_authority_record_hash",
        "split_authority_artifact_sha256s",
        "split_authority_record_hashes",
        "frozen_run_spec_artifact_sha256",
        "frozen_run_spec_record_hash",
        "execution_run_id",
        "authority_scope",
        "scientific_evidence",
    }
    if set(value) != required:
        raise DomainInputError("scientific domain plan schema is not exact")
    if (
        record.logical_type
        != _scientific_domain_plan_logical_type(expected_domain)
        or record.schema_version
        != SCIENTIFIC_DOMAIN_EVIDENCE_PLAN_ARTIFACT_SCHEMA_VERSION
        or record.mime_type != "application/json"
        or record.origin
        != _scientific_domain_plan_origin(expected_domain, expected_object_id)
        or record.creator_role is not Role.PROTOCOL_DESIGNER
        or record.creation_command != _SCIENTIFIC_DOMAIN_PLAN_COMMAND
        or record.validation_result != "PASS"
        or record.frozen is not True
        or value["schema_version"]
        != SCIENTIFIC_DOMAIN_EVIDENCE_PLAN_SCHEMA_VERSION
        or value["run_id"] != expected_run_id
        or value["domain"] != expected_domain.value
        or value["object_id"] != expected_object_id
        or value["task_id"] != expected_task_id
        or value["authority_scope"] != "PROSPECTIVE_DOMAIN_POLICY_ONLY"
        or value["scientific_evidence"] is not False
        or not isinstance(value["split_authority_artifact_sha256s"], list)
        or not isinstance(value["split_authority_record_hashes"], list)
    ):
        raise DomainInputError("scientific domain plan identity is substituted")
    profile = _scientific_domain_profile(
        expected_domain,
        str(value["source_format_id"]),
        str(value["source_format_version"]),
    )
    if (
        value["attestation_schema"] != profile.attestation_schema
        or value["verifier_id"] != profile.verifier_id
    ):
        raise DomainInputError(
            "scientific domain plan trust-verifier identity is substituted"
        )
    if enforce_not_revoked:
        _reject_revoked_scientific_domain_trust_root(
            ledger_result.events,
            trust_root_id=str(value["trust_root_id"]),
            plan_artifact_sha256=record.sha256,
        )
    if enforce_trust_root:
        _trust_key, trust_root_id = (
            _require_scientific_domain_profile_trust_root(
                registry,
                profile,
                expected_trust_root_id=str(value["trust_root_id"]),
            )
        )
    else:
        trust_root_id = str(value["trust_root_id"])
        _validate_sha256(trust_root_id, "scientific domain trust-root ID")
    try:
        split_hashes = tuple(value["split_authority_artifact_sha256s"])
        _contract, _dataset, _splits, spec, records = (
            _replay_scientific_domain_plan_sources(
                registry,
                ledger,
                run_id=expected_run_id,
                domain=expected_domain,
                object_id=expected_object_id,
                task_id=expected_task_id,
                source_format_id=str(value["source_format_id"]),
                source_format_version=str(value["source_format_version"]),
                evaluation_contract_artifact_sha256=str(
                    value["evaluation_contract_artifact_sha256"]
                ),
                dataset_authority_artifact_sha256=str(
                    value["dataset_authority_artifact_sha256"]
                ),
                split_authority_artifact_sha256s=split_hashes,
                frozen_run_spec_artifact_sha256=str(
                    value["frozen_run_spec_artifact_sha256"]
                ),
            )
        )
    except (TypeError, ValueError) as exc:
        raise DomainInputError("scientific domain plan sources are malformed") from exc
    expected_payload = _scientific_domain_plan_payload(
        run_id=expected_run_id,
        domain=expected_domain,
        object_id=expected_object_id,
        task_id=expected_task_id,
        source_format_id=str(value["source_format_id"]),
        source_format_version=str(value["source_format_version"]),
        records=records,
        execution_run_id=spec.run_id,
        attestation_schema=profile.attestation_schema,
        verifier_id=profile.verifier_id,
        trust_root_id=trust_root_id,
    )
    if dict(value) != expected_payload or record.parent_artifacts != tuple(
        item.sha256 for item in records
    ):
        raise DomainInputError(
            "scientific domain plan differs from freshly replayed authorities"
        )
    slot_records = _scientific_domain_plan_slot_records(
        registry,
        registry_result.records,
        run_id=expected_run_id,
        object_id=expected_object_id,
        task_id=expected_task_id,
    )
    if slot_records != (record,):
        raise DomainInputError("scientific domain plan slot is ambiguous")
    event_id = _scientific_domain_plan_event_id(record.sha256)
    matches = tuple(
        (index, event)
        for index, event in enumerate(ledger_result.events)
        if event.event_id == event_id
    )
    if len(matches) != 1 or matches[0][0] == 0:
        raise DomainInputError(
            "scientific domain plan lacks one exact prospective ledger event"
        )
    event_index, event = matches[0]
    prior = ledger_result.events[event_index - 1]
    expected_event = LedgerEvent.create(
        run_id=expected_run_id,
        actor_role=Role.PROTOCOL_DESIGNER,
        state_before=prior.requested_state_after,
        requested_state_after=prior.requested_state_after,
        artifact_hashes=(record.sha256,),
        code_version=prior.code_version,
        configuration_hash=prior.configuration_hash,
        dataset_identifiers=(_dataset.dataset_id,),
        random_seeds=spec.seeds,
        reason=(
            "froze domain, task, evaluation, Dataset, split, and source-format "
            "policy before scientific execution preparation"
        ),
        prior_event_hash=prior.event_hash,
        event_id=event_id,
        timestamp=record.created_at,
        event_type="CHECKPOINT",
        metadata=_scientific_domain_plan_event_metadata(value, record),
    )
    preparation_indexes = tuple(
        index
        for index, candidate in enumerate(ledger_result.events)
        if isinstance(
            thaw_json(candidate.metadata).get(
                "scientific_execution_preparation"
            ),
            Mapping,
        )
        and thaw_json(candidate.metadata)["scientific_execution_preparation"].get(
            "frozen_run_spec_artifact_sha256"
        )
        == value["frozen_run_spec_artifact_sha256"]
    )
    if (
        event != expected_event
        or any(index <= event_index for index in preparation_indexes)
        or any(
            candidate.event_type == "CORRECTION"
            and candidate.supersedes_event_id == event.event_id
            for candidate in ledger_result.events[event_index + 1 :]
        )
    ):
        raise DomainInputError(
            "scientific domain plan event is stale, substituted, or post-execution"
        )
    return ScientificDomainEvidencePlan(
        plan_artifact_sha256=record.sha256,
        plan_record_hash=str(record.record_hash),
        run_id=expected_run_id,
        domain=expected_domain,
        object_id=expected_object_id,
        task_id=expected_task_id,
        source_format_id=str(value["source_format_id"]),
        source_format_version=str(value["source_format_version"]),
        attestation_schema=profile.attestation_schema,
        verifier_id=profile.verifier_id,
        trust_root_id=trust_root_id,
        evaluation_contract_artifact_sha256=records[0].sha256,
        evaluation_contract_record_hash=str(records[0].record_hash),
        dataset_authority_artifact_sha256=records[1].sha256,
        dataset_authority_record_hash=str(records[1].record_hash),
        split_authority_artifact_sha256s=tuple(
            record.sha256 for record in records[2:6]
        ),
        split_authority_record_hashes=tuple(
            str(record.record_hash) for record in records[2:6]
        ),
        frozen_run_spec_artifact_sha256=records[6].sha256,
        frozen_run_spec_record_hash=str(records[6].record_hash),
        execution_run_id=spec.run_id,
        ledger_event_id=event.event_id,
        ledger_event_hash=str(event.event_hash),
        ledger_event_index=event_index,
    )


def require_scientific_domain_evidence_plan(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    plan_artifact_sha256: str,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
) -> ScientificDomainEvidencePlan:
    """Freshly replay a prospective plan, current root, and revocation state."""

    return _require_scientific_domain_evidence_plan(
        registry,
        ledger,
        plan_artifact_sha256=plan_artifact_sha256,
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
        enforce_trust_root=True,
        enforce_not_revoked=True,
    )


def _validate_scientific_domain_trust_revocation_event(
    events: tuple[LedgerEvent, ...],
    *,
    event_index: int,
    event: LedgerEvent,
    run_id: str,
    plan_artifact_sha256: str,
    plan_record_hash: str,
    plan_event_id: str,
    domain: DomainKind,
    source_format_id: str,
    source_format_version: str,
    attestation_schema: str,
    verifier_id: str,
    trust_root_id: str,
    dataset_authority_artifact_sha256: str,
) -> None:
    if event_index == 0:
        raise DomainInputError(
            "scientific domain trust-root revocation cannot initialize a ledger"
        )
    prior = events[event_index - 1]
    plan_indexes = tuple(
        index
        for index, candidate in enumerate(events[:event_index])
        if candidate.event_id == plan_event_id
    )
    expected = LedgerEvent.create(
        run_id=run_id,
        actor_role=Role.ORCHESTRATOR,
        state_before=prior.requested_state_after,
        requested_state_after=prior.requested_state_after,
        artifact_hashes=(plan_artifact_sha256,),
        code_version=prior.code_version,
        configuration_hash=prior.configuration_hash,
        dataset_identifiers=(dataset_authority_artifact_sha256,),
        random_seeds=(),
        reason=(
            "irreversibly revoked the pinned local scientific-domain trust root"
        ),
        prior_event_hash=prior.event_hash,
        event_id=_scientific_domain_trust_revocation_event_id(trust_root_id),
        timestamp=event.timestamp,
        event_type="CHECKPOINT",
        metadata=_scientific_domain_trust_revocation_metadata_values(
            plan_artifact_sha256=plan_artifact_sha256,
            plan_record_hash=plan_record_hash,
            domain=domain,
            source_format_id=source_format_id,
            source_format_version=source_format_version,
            attestation_schema=attestation_schema,
            verifier_id=verifier_id,
            trust_root_id=trust_root_id,
        ),
    )
    if len(plan_indexes) != 1 or event != expected:
        raise DomainInputError(
            "scientific domain trust-root revocation marker is substituted"
        )


def revoke_scientific_domain_trust_root(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    plan_artifact_sha256: str,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
) -> LedgerEvent:
    """Irreversibly deny one prospectively pinned per-registry trust root."""

    validate_identifier(expected_run_id, "expected scientific domain run ID")
    validate_identifier(expected_object_id, "expected scientific domain object ID")
    validate_identifier(expected_task_id, "expected scientific domain task ID")
    if not isinstance(expected_domain, DomainKind):
        raise DomainInputError("expected scientific domain must be typed")
    plan = _require_scientific_domain_evidence_plan(
        registry,
        ledger,
        plan_artifact_sha256=plan_artifact_sha256,
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
        enforce_trust_root=False,
        enforce_not_revoked=False,
    )
    _registry_result, ledger_result = _require_scientific_domain_runtime(
        registry,
        ledger,
        run_id=expected_run_id,
    )
    matches = _scientific_domain_trust_revocation_candidates(
        ledger_result.events,
        trust_root_id=plan.trust_root_id,
        plan_artifact_sha256=plan.plan_artifact_sha256,
    )
    if len(matches) > 1:
        raise DomainInputError(
            "scientific domain trust-root revocation marker is ambiguous"
        )
    if matches:
        event_index, existing = matches[0]
        _validate_scientific_domain_trust_revocation_event(
            ledger_result.events,
            event_index=event_index,
            event=existing,
            run_id=expected_run_id,
            plan_artifact_sha256=plan.plan_artifact_sha256,
            plan_record_hash=plan.plan_record_hash,
            plan_event_id=plan.ledger_event_id,
            domain=plan.domain,
            source_format_id=plan.source_format_id,
            source_format_version=plan.source_format_version,
            attestation_schema=plan.attestation_schema,
            verifier_id=plan.verifier_id,
            trust_root_id=plan.trust_root_id,
            dataset_authority_artifact_sha256=(
                plan.dataset_authority_artifact_sha256
            ),
        )
        return existing
    registry_snapshot, ledger_snapshot = _require_scientific_domain_runtime(
        registry,
        ledger,
        run_id=expected_run_id,
    )
    if (
        ledger_snapshot.event_count >= MAX_LEDGER_EVENTS
        or ledger.path.stat().st_size + 16_384 > MAX_LEDGER_BYTES
    ):
        raise DomainInputError(
            "scientific domain trust-root revocation exceeds ledger capacity"
        )
    prior = ledger_snapshot.events[-1]
    event = LedgerEvent.create(
        run_id=expected_run_id,
        actor_role=Role.ORCHESTRATOR,
        state_before=prior.requested_state_after,
        requested_state_after=prior.requested_state_after,
        artifact_hashes=(plan.plan_artifact_sha256,),
        code_version=prior.code_version,
        configuration_hash=prior.configuration_hash,
        dataset_identifiers=(plan.dataset_authority_artifact_sha256,),
        random_seeds=(),
        reason=(
            "irreversibly revoked the pinned local scientific-domain trust root"
        ),
        prior_event_hash=prior.event_hash,
        event_id=_scientific_domain_trust_revocation_event_id(plan.trust_root_id),
        timestamp=utc_now(),
        event_type="CHECKPOINT",
        metadata=_scientific_domain_trust_revocation_metadata(plan),
    )
    registry_guard = registry._open_mutation_lock()
    try:
        registry._assert_snapshot_locked(registry_guard, registry_snapshot)
        ledger_guard = ledger._lock()
        try:
            ledger._assert_snapshot_locked(ledger_guard, ledger_snapshot)

            def build_event(
                _prior_event: LedgerEvent | None,
                _events: tuple[LedgerEvent, ...],
            ) -> LedgerEvent:
                registry._assert_snapshot_locked(
                    registry_guard,
                    registry_snapshot,
                )
                ledger._assert_snapshot_locked(ledger_guard, ledger_snapshot)
                return event

            appended = ledger._append_locked(ledger_guard, build_event)
            if appended != event:
                raise DomainInputError(
                    "scientific domain trust-root revocation changed during commit"
                )
        finally:
            ledger._unlock(ledger_guard)
        registry._verify_mutation_namespace(registry_guard)
    finally:
        registry._unlock_mutation(registry_guard)
    events = _require_scientific_domain_runtime(
        registry,
        ledger,
        run_id=expected_run_id,
    )[1].events
    matches = _scientific_domain_trust_revocation_candidates(
        events,
        trust_root_id=plan.trust_root_id,
        plan_artifact_sha256=plan.plan_artifact_sha256,
    )
    if len(matches) != 1:
        raise DomainInputError(
            "scientific domain trust-root revocation did not commit exactly once"
        )
    _validate_scientific_domain_trust_revocation_event(
        events,
        event_index=matches[0][0],
        event=matches[0][1],
        run_id=expected_run_id,
        plan_artifact_sha256=plan.plan_artifact_sha256,
        plan_record_hash=plan.plan_record_hash,
        plan_event_id=plan.ledger_event_id,
        domain=plan.domain,
        source_format_id=plan.source_format_id,
        source_format_version=plan.source_format_version,
        attestation_schema=plan.attestation_schema,
        verifier_id=plan.verifier_id,
        trust_root_id=plan.trust_root_id,
        dataset_authority_artifact_sha256=(
            plan.dataset_authority_artifact_sha256
        ),
    )
    return matches[0][1]


def _scientific_domain_raw_logical_type(
    domain: DomainKind,
    source_format_id: str,
) -> str:
    return (
        f"scientific_domain_raw_source.{_domain_slug(domain)}."
        f"{source_format_id}"
    )


def _scientific_domain_raw_origin(
    domain: DomainKind,
    object_id: str,
    source_format_id: str,
) -> str:
    return (
        f"trusted-kernel {domain.value} observations {source_format_id} "
        f"for {object_id}"
    )


def _scientific_domain_source_origin(
    domain: DomainKind,
    object_id: str,
) -> str:
    return f"source-verified {domain.value} domain evidence for {object_id}"


def _parse_trusted_kernel_generic_ml_prediction_bytes(
    raw: bytes,
    *,
    execution_run_id: str,
    model_artifact_sha256: str,
    evaluator_artifact_sha256: str,
    confirmatory_split_authority_artifact_sha256: str,
    metric_policy: Mapping[str, object],
    expected_example_ids: tuple[str, ...],
    expected_example_hashes: tuple[str, ...],
) -> tuple[tuple[int, ...], tuple[int, ...], float]:
    """Parse one exact reference-accuracy output without granting authority."""

    try:
        value = safe_json_loads(raw)
    except (UnsafeSerializationError, ValidationError) as exc:
        raise DomainInputError(
            "Generic-ML prediction bytes are not safe canonical JSON"
        ) from exc
    required = {
        "schema_version",
        "execution_run_id",
        "model_artifact_sha256",
        "evaluator_artifact_sha256",
        "confirmatory_split_authority_artifact_sha256",
        "metric_policy",
        "reported_accuracy",
        "rows",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != required
        or raw != canonical_json_bytes(value) + b"\n"
        or value["schema_version"]
        != _SCIENTIFIC_DOMAIN_GENERIC_ML_PREDICTIONS_SCHEMA
        or value["execution_run_id"] != execution_run_id
        or value["model_artifact_sha256"] != model_artifact_sha256
        or value["evaluator_artifact_sha256"] != evaluator_artifact_sha256
        or value["confirmatory_split_authority_artifact_sha256"]
        != confirmatory_split_authority_artifact_sha256
        or value["metric_policy"] != metric_policy
        or type(value["reported_accuracy"]) is not float
        or not isinstance(value["rows"], list)
        or not value["rows"]
        or len(value["rows"]) > MAX_DOMAIN_RECORDS
        or len(expected_example_ids) != len(expected_example_hashes)
    ):
        raise DomainInputError(
            "Generic-ML prediction bytes have the wrong closed output schema"
        )
    labels: list[int] = []
    predictions: list[int] = []
    observed_ids: list[str] = []
    observed_hashes: list[str] = []
    for row in value["rows"]:
        if not isinstance(row, Mapping) or set(row) != {
            "example_id",
            "example_sha256",
            "expected_label",
            "prediction",
        }:
            raise DomainInputError("Generic-ML prediction row is malformed")
        example_id = row["example_id"]
        _validate_text(example_id, "Generic-ML prediction example ID")
        example_sha256 = row["example_sha256"]
        _validate_sha256(example_sha256, "Generic-ML prediction example hash")
        expected_label = row["expected_label"]
        prediction = row["prediction"]
        if (
            isinstance(expected_label, bool)
            or not isinstance(expected_label, int)
            or isinstance(prediction, bool)
            or not isinstance(prediction, int)
        ):
            raise DomainInputError(
                "Generic-ML prediction labels and values must be integers"
            )
        observed_ids.append(example_id)
        observed_hashes.append(example_sha256)
        labels.append(expected_label)
        predictions.append(prediction)
    if (
        tuple(observed_ids) != expected_example_ids
        or tuple(observed_hashes) != expected_example_hashes
    ):
        raise DomainInputError(
            "Generic-ML prediction bytes do not cover the exact confirmatory inputs"
        )
    accuracy = sum(
        int(expected == predicted)
        for expected, predicted in zip(labels, predictions, strict=True)
    ) / len(labels)
    if value["reported_accuracy"] != accuracy:
        raise DomainInputError(
            "Generic-ML prediction output differs from reference accuracy"
        )
    return tuple(labels), tuple(predictions), accuracy


def _validate_trusted_kernel_generic_ml_robustness_bytes(
    raw: bytes,
    *,
    execution_run_id: str,
    robustness_test_id: str,
    candidate_model_artifact_sha256: str,
    evaluator_artifact_sha256: str,
    confirmatory_split_authority_artifact_sha256: str,
) -> None:
    """Validate one exact robustness-completion output without authority."""

    try:
        value = safe_json_loads(raw)
    except (UnsafeSerializationError, ValidationError) as exc:
        raise DomainInputError(
            "Generic-ML robustness bytes are not safe canonical JSON"
        ) from exc
    if (
        not isinstance(value, Mapping)
        or set(value)
        != {
            "schema_version",
            "execution_run_id",
            "robustness_test_id",
            "candidate_model_artifact_sha256",
            "evaluator_artifact_sha256",
            "confirmatory_split_authority_artifact_sha256",
            "status",
        }
        or raw != canonical_json_bytes(value) + b"\n"
        or value["schema_version"]
        != _SCIENTIFIC_DOMAIN_GENERIC_ML_ROBUSTNESS_SCHEMA
        or value["execution_run_id"] != execution_run_id
        or value["robustness_test_id"] != robustness_test_id
        or value["candidate_model_artifact_sha256"]
        != candidate_model_artifact_sha256
        or value["evaluator_artifact_sha256"] != evaluator_artifact_sha256
        or value["confirmatory_split_authority_artifact_sha256"]
        != confirmatory_split_authority_artifact_sha256
        or value["status"] != "COMPLETED"
    ):
        raise DomainInputError(
            "Generic-ML robustness bytes have the wrong source-owned schema"
        )


def _require_trusted_kernel_observed_domain_policy(
    observed: object,
    prospective: object,
) -> Mapping[str, object]:
    if not isinstance(observed, Mapping) or observed != prospective:
        raise DomainInputError(
            "Generic-ML observed execution policy differs from the prospective policy"
        )
    return observed


def _validate_trusted_kernel_generic_ml_observation_shape(
    observations: object,
) -> Mapping[str, object]:
    """Validate the closed observation envelope without granting authority."""

    required = {
        "schema_version",
        "actual_domain_policy",
        "loaded_pretrained_resource_inventory",
        "models",
        "metric_evaluation",
        "robustness_outputs",
    }
    if (
        not isinstance(observations, Mapping)
        or set(observations) != required
        or observations.get("schema_version")
        != "trusted-kernel-generic-ml-observations/v1"
    ):
        raise DomainInputError("Generic-ML source observations schema is not exact")
    models = observations["models"]
    if not isinstance(models, Mapping) or set(models) != {
        "baseline_id",
        "candidate_model_artifact_sha256",
        "candidate_model_record_hash",
        "baseline_model_artifact_sha256",
        "baseline_model_record_hash",
        "candidate_parameter_count",
        "baseline_parameter_count",
    }:
        raise DomainInputError("Generic-ML model observations are malformed")
    _validate_text(models["baseline_id"], "Generic-ML baseline ID")
    for name in (
        "candidate_model_artifact_sha256",
        "candidate_model_record_hash",
        "baseline_model_artifact_sha256",
        "baseline_model_record_hash",
    ):
        _validate_sha256(models[name], f"Generic-ML {name}")
    _validate_count(
        models["candidate_parameter_count"],
        "Generic-ML candidate parameter count",
    )
    _validate_count(
        models["baseline_parameter_count"],
        "Generic-ML baseline parameter count",
    )
    metric = observations["metric_evaluation"]
    if not isinstance(metric, Mapping) or set(metric) != {
        "metric_id",
        "evaluator_artifact_sha256",
        "evaluator_record_hash",
        "confirmatory_split_authority_artifact_sha256",
        "confirmatory_split_authority_record_hash",
        "candidate_model_artifact_sha256",
        "baseline_model_artifact_sha256",
        "candidate_predictions_artifact_sha256",
        "candidate_predictions_record_hash",
        "baseline_predictions_artifact_sha256",
        "baseline_predictions_record_hash",
        "candidate_accuracy",
        "baseline_accuracy",
    }:
        raise DomainInputError("Generic-ML metric observations are malformed")
    _validate_text(metric["metric_id"], "Generic-ML metric ID")
    for name in (
        "evaluator_artifact_sha256",
        "evaluator_record_hash",
        "confirmatory_split_authority_artifact_sha256",
        "confirmatory_split_authority_record_hash",
        "candidate_model_artifact_sha256",
        "baseline_model_artifact_sha256",
        "candidate_predictions_artifact_sha256",
        "candidate_predictions_record_hash",
        "baseline_predictions_artifact_sha256",
        "baseline_predictions_record_hash",
    ):
        _validate_sha256(metric[name], f"Generic-ML {name}")
    for name in ("candidate_accuracy", "baseline_accuracy"):
        if type(metric[name]) is not float or not 0.0 <= metric[name] <= 1.0:
            raise DomainInputError(f"Generic-ML {name} is not a fraction")
    inventory = observations["loaded_pretrained_resource_inventory"]
    if (
        not isinstance(inventory, Mapping)
        or set(inventory)
        != {"schema_version", "completeness", "artifact_sha256s"}
        or inventory.get("schema_version")
        != _SCIENTIFIC_DOMAIN_GENERIC_ML_PRETRAINED_INVENTORY_SCHEMA
        or inventory.get("completeness") != "EXHAUSTIVE"
        or not isinstance(inventory.get("artifact_sha256s"), list)
        or len(inventory["artifact_sha256s"]) > MAX_DOMAIN_RECORDS
    ):
        raise DomainInputError(
            "Generic-ML loaded pretrained-resource inventory is not exhaustive"
        )
    for digest in inventory["artifact_sha256s"]:
        _validate_sha256(digest, "Generic-ML loaded pretrained resource")
    robustness = observations["robustness_outputs"]
    if not isinstance(robustness, list) or len(robustness) > MAX_DOMAIN_CHECKS:
        raise DomainInputError("Generic-ML robustness results are not bounded")
    for value in robustness:
        if not isinstance(value, Mapping) or set(value) != {
            "robustness_test_id",
            "artifact_sha256",
            "artifact_record_hash",
        }:
            raise DomainInputError("Generic-ML robustness result is malformed")
        _validate_text(value["robustness_test_id"], "Generic-ML robustness test ID")
        _validate_sha256(value["artifact_sha256"], "Generic-ML robustness output")
        _validate_sha256(
            value["artifact_record_hash"],
            "Generic-ML robustness output record",
        )
    return observations


def _derive_trusted_kernel_generic_ml_observations(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    candidate: _ScientificDomainSourceCandidate,
) -> _ScientificDomainVerifiedEvidence:
    """Derive typed ML evidence from owners plus authenticated observations."""

    try:
        contract, dataset_authority, split_authorities, spec, _records = (
            _replay_scientific_domain_plan_sources(
                registry,
                ledger,
                run_id=candidate.plan.run_id,
                domain=candidate.plan.domain,
                object_id=candidate.plan.object_id,
                task_id=candidate.plan.task_id,
                source_format_id=candidate.plan.source_format_id,
                source_format_version=candidate.plan.source_format_version,
                evaluation_contract_artifact_sha256=(
                    candidate.plan.evaluation_contract_artifact_sha256
                ),
                dataset_authority_artifact_sha256=(
                    candidate.plan.dataset_authority_artifact_sha256
                ),
                split_authority_artifact_sha256s=(
                    candidate.plan.split_authority_artifact_sha256s
                ),
                frozen_run_spec_artifact_sha256=(
                    candidate.plan.frozen_run_spec_artifact_sha256
                ),
            )
        )
    except Exception as exc:
        raise DomainInputError(
            "Generic-ML source lost its prospective authorities"
        ) from exc
    observations = _validate_trusted_kernel_generic_ml_observation_shape(
        candidate.raw_source_payload["domain_observations"]
    )
    split_id_to_role = {
        split_authorities[0].split_id: SplitRole.TRAIN,
        split_authorities[1].split_id: SplitRole.VALIDATION,
        split_authorities[2].split_id: SplitRole.VALIDATION,
        split_authorities[3].split_id: SplitRole.HOLDOUT,
    }
    examples = tuple(
        GenericMLExample(example_id=unit_id, split=role)
        for split, role in zip(
            split_authorities,
            (
                SplitRole.TRAIN,
                SplitRole.VALIDATION,
                SplitRole.VALIDATION,
                SplitRole.HOLDOUT,
            ),
            strict=True,
        )
        for unit_id in split.member_unit_ids
    )
    if len({item.example_id for item in examples}) != len(examples):
        raise DomainInputError(
            "Generic-ML Dataset split authorities contain duplicate examples"
        )

    def split_roles(value: object, label: str) -> tuple[SplitRole, ...]:
        if (
            not isinstance(value, list)
            or len(value) > 4
            or any(not isinstance(item, str) for item in value)
            or len(set(value)) != len(value)
            or any(item not in split_id_to_role for item in value)
        ):
            raise DomainInputError(f"{label} is not an exact split-ID list")
        result: list[SplitRole] = []
        for item in value:
            role = split_id_to_role[item]
            if role not in result:
                result.append(role)
        return tuple(result)

    prospective_policy = thaw_json(spec.metadata)["scientific_domain_policy"]
    actual_policy = _require_trusted_kernel_observed_domain_policy(
        observations["actual_domain_policy"],
        prospective_policy,
    )
    preprocessing_splits = split_roles(
        actual_policy["preprocessing_fit_split_ids"],
        "Generic-ML preprocessing split observations",
    )
    checkpoint_split_id = actual_policy["checkpoint_selection_split_id"]
    if checkpoint_split_id is not None and checkpoint_split_id not in split_id_to_role:
        raise DomainInputError(
            "Generic-ML checkpoint selection names an unknown split"
        )
    checkpoint_split = (
        None
        if checkpoint_split_id is None
        else split_id_to_role[checkpoint_split_id]
    )

    early = actual_policy["early_stopping"]
    if not isinstance(early, Mapping) or set(early) != {
        "enabled",
        "monitor_split_id",
    }:
        raise DomainInputError("Generic-ML early-stopping observations are malformed")
    if type(early["enabled"]) is not bool:
        raise DomainInputError("Generic-ML early-stopping enabled fact is not boolean")
    early_monitor = early["monitor_split_id"]
    if early_monitor is not None and early_monitor not in split_id_to_role:
        raise DomainInputError("Generic-ML early stopping names an unknown split")
    early_stopping = EarlyStoppingPolicyEvidence(
        enabled=early["enabled"],
        monitor_split=(
            None if early_monitor is None else split_id_to_role[early_monitor]
        ),
        policy_artifact_sha256=candidate.plan.frozen_run_spec_artifact_sha256,
        timing=MLPolicyTiming.FROZEN_BEFORE_RESULTS,
    )

    augmentation_value = actual_policy["augmentation"]
    if not isinstance(augmentation_value, Mapping) or set(augmentation_value) != {
        "mode",
        "fit_split_ids",
        "application_split_ids",
    }:
        raise DomainInputError("Generic-ML augmentation observations are malformed")
    try:
        augmentation_mode = AugmentationMode(augmentation_value["mode"])
    except (TypeError, ValueError) as exc:
        raise DomainInputError("Generic-ML augmentation mode is unknown") from exc
    augmentation = AugmentationPolicyEvidence(
        mode=augmentation_mode,
        fit_splits=split_roles(
            augmentation_value["fit_split_ids"],
            "Generic-ML augmentation fit splits",
        ),
        application_splits=split_roles(
            augmentation_value["application_split_ids"],
            "Generic-ML augmentation application splits",
        ),
        policy_artifact_sha256=candidate.plan.frozen_run_spec_artifact_sha256,
        timing=MLPolicyTiming.FROZEN_BEFORE_RESULTS,
    )

    authority = candidate.scientific_execution_authority
    semantic_records: list[ArtifactRecord] = []

    def execution_output_record(
        digest: object,
        record_hash: object,
        label: str,
    ) -> ArtifactRecord:
        _validate_sha256(digest, label)
        _validate_sha256(record_hash, f"{label} record")
        matching_indexes = tuple(
            index
            for index, value in enumerate(authority.output_artifact_sha256s)
            if value == digest
        )
        if len(matching_indexes) != 1:
            raise DomainInputError(
                f"{label} is not one exact scientific execution output"
            )
        index = matching_indexes[0]
        try:
            registry.verify(digest, raise_on_error=True)
            record = registry.get_metadata(digest)
        except (ArtifactError, ValidationError) as exc:
            raise DomainInputError(f"{label} cannot be reopened") from exc
        if (
            authority.output_artifact_record_hashes[index] != record_hash
            or record.record_hash != record_hash
            or record.creator_role is not Role.EXPERIMENT_RUNNER
            or record.validation_result != "PASS"
            or record.frozen is not True
            or not record.logical_type.startswith("experiment_output.")
        ):
            raise DomainInputError(
                f"{label} metadata differs from execution authority"
            )
        if record not in semantic_records:
            semantic_records.append(record)
        return record

    models = observations["models"]
    model_keys = {
        "baseline_id",
        "candidate_model_artifact_sha256",
        "candidate_model_record_hash",
        "baseline_model_artifact_sha256",
        "baseline_model_record_hash",
        "candidate_parameter_count",
        "baseline_parameter_count",
    }
    if not isinstance(models, Mapping) or set(models) != model_keys:
        raise DomainInputError("Generic-ML model observations are malformed")
    active_baselines = tuple(
        item
        for item in contract.baseline_registry.entries
        if item.status.value not in {"CONTEXT_ONLY", "INCOMPATIBLE"}
    )
    if (
        len(active_baselines) != 1
        or models["baseline_id"] != active_baselines[0].baseline_id
    ):
        raise DomainInputError(
            "trusted-kernel Generic-ML observations support exactly one comparator"
        )
    candidate_model_record = execution_output_record(
        models["candidate_model_artifact_sha256"],
        models["candidate_model_record_hash"],
        "Generic-ML candidate-model artifact",
    )
    baseline_model_record = execution_output_record(
        models["baseline_model_artifact_sha256"],
        models["baseline_model_record_hash"],
        "Generic-ML baseline-model artifact",
    )
    candidate_count = models["candidate_parameter_count"]
    baseline_count = models["baseline_parameter_count"]
    for value, label in (
        (candidate_count, "candidate parameter count"),
        (baseline_count, "baseline parameter count"),
    ):
        _validate_count(value, f"Generic-ML {label}")
    baseline_conditions = active_baselines[0].conditions
    candidate_conditions = contract.candidate_conditions
    environment_record = registry.get_metadata(
        authority.environment_artifact_sha256
    )
    if (
        environment_record.record_hash != authority.environment_record_hash
        or environment_record.validation_result != "PASS"
        or environment_record.frozen is not True
        or environment_record.creator_role is not Role.EXPERIMENT_RUNNER
    ):
        raise DomainInputError(
            "Generic-ML execution environment authority is not exact"
        )
    if environment_record not in semantic_records:
        semantic_records.append(environment_record)
    resource_equivalent = all(
        getattr(candidate_conditions, field_name)
        == getattr(baseline_conditions, field_name)
        for field_name in (
            "hardware_class",
            "latency_method",
            "compute_budget",
        )
    )
    model_comparison = ModelResourceComparisonEvidence(
        candidate_parameter_count=candidate_count,
        baseline_parameter_count=baseline_count,
        candidate_resource_profile_sha256=environment_record.sha256,
        baseline_resource_profile_sha256=environment_record.sha256,
        parameter_count_disposition=(
            ComparisonDisposition.COMPARABLE
            if candidate_count == baseline_count
            else ComparisonDisposition.UNFAIR
        ),
        resource_disposition=(
            ComparisonDisposition.COMPARABLE
            if resource_equivalent
            else ComparisonDisposition.UNFAIR
        ),
        comparison_artifact_sha256=candidate.raw_source_record.sha256,
    )

    metric = observations["metric_evaluation"]
    metric_keys = {
        "metric_id",
        "evaluator_artifact_sha256",
        "evaluator_record_hash",
        "confirmatory_split_authority_artifact_sha256",
        "confirmatory_split_authority_record_hash",
        "candidate_model_artifact_sha256",
        "baseline_model_artifact_sha256",
        "candidate_predictions_artifact_sha256",
        "candidate_predictions_record_hash",
        "baseline_predictions_artifact_sha256",
        "baseline_predictions_record_hash",
        "candidate_accuracy",
        "baseline_accuracy",
    }
    if not isinstance(metric, Mapping) or set(metric) != metric_keys:
        raise DomainInputError("Generic-ML metric observations are malformed")
    metric_policy = prospective_policy["metric_policy"]
    evaluator_record = registry.get_metadata(spec.evaluator_sha256)
    confirmatory_record = _records[5]
    if (
        metric_policy
        != {
            "schema_version": _SCIENTIFIC_DOMAIN_GENERIC_ML_POLICY_SCHEMA,
            "metric_id": contract.primary_metric.metric_id,
            "semantics": "EXACT_INTEGER_LABEL_MATCH",
            "aggregation": "MICRO_EXAMPLE_MEAN",
            "unit": "FRACTION",
            "direction": "HIGHER_IS_BETTER",
        }
        or contract.primary_metric.unit.value != "FRACTION"
        or contract.primary_metric.direction.value != "HIGHER_IS_BETTER"
        or contract.primary_metric.aggregation != "MICRO_EXAMPLE_MEAN"
        or metric["metric_id"] != contract.primary_metric.metric_id
        or metric["evaluator_artifact_sha256"] != spec.evaluator_sha256
        or metric["evaluator_record_hash"] != evaluator_record.record_hash
        or metric["confirmatory_split_authority_artifact_sha256"]
        != split_authorities[3].artifact_hash
        or metric["confirmatory_split_authority_record_hash"]
        != split_authorities[3].record_hash
        or metric["candidate_model_artifact_sha256"]
        != candidate_model_record.sha256
        or metric["baseline_model_artifact_sha256"]
        != baseline_model_record.sha256
        or evaluator_record.validation_result != "PASS"
        or evaluator_record.frozen is not True
        or evaluator_record.creator_role is Role.HUMAN_RELEASE
        or confirmatory_record.record_hash != split_authorities[3].record_hash
    ):
        raise DomainInputError(
            "Generic-ML metric evaluation is not the closed reference-accuracy profile"
        )
    if evaluator_record not in semantic_records:
        semantic_records.append(evaluator_record)
    if confirmatory_record not in semantic_records:
        semantic_records.append(confirmatory_record)

    candidate_predictions_record = execution_output_record(
        metric["candidate_predictions_artifact_sha256"],
        metric["candidate_predictions_record_hash"],
        "Generic-ML candidate prediction artifact",
    )
    baseline_predictions_record = execution_output_record(
        metric["baseline_predictions_artifact_sha256"],
        metric["baseline_predictions_record_hash"],
        "Generic-ML baseline prediction artifact",
    )

    def prediction_rows(
        record: ArtifactRecord,
        *,
        model_artifact_sha256: str,
        label: str,
    ) -> tuple[tuple[int, ...], tuple[int, ...], float]:
        try:
            raw = registry.get_bytes(record.sha256)
        except (ArtifactError, ValidationError) as exc:
            raise DomainInputError(f"{label} cannot be parsed") from exc
        if (
            record.logical_type != "experiment_output.generic_ml_predictions"
            or record.schema_version
            != _SCIENTIFIC_DOMAIN_GENERIC_ML_PREDICTIONS_ARTIFACT_SCHEMA
            or record.mime_type != "application/json"
        ):
            raise DomainInputError(f"{label} has the wrong closed output schema")
        return _parse_trusted_kernel_generic_ml_prediction_bytes(
            raw,
            execution_run_id=candidate.plan.execution_run_id,
            model_artifact_sha256=model_artifact_sha256,
            evaluator_artifact_sha256=evaluator_record.sha256,
            confirmatory_split_authority_artifact_sha256=(
                confirmatory_record.sha256
            ),
            metric_policy=metric_policy,
            expected_example_ids=tuple(
                split_authorities[3].member_unit_ids
            ),
            expected_example_hashes=tuple(
                split_authorities[3].member_unit_hashes
            ),
        )

    candidate_labels, _candidate_predictions, candidate_output_accuracy = (
        prediction_rows(
        candidate_predictions_record,
        model_artifact_sha256=candidate_model_record.sha256,
        label="Generic-ML candidate predictions",
        )
    )
    baseline_labels, _baseline_predictions, baseline_output_accuracy = (
        prediction_rows(
        baseline_predictions_record,
        model_artifact_sha256=baseline_model_record.sha256,
        label="Generic-ML baseline predictions",
        )
    )
    if candidate_labels != baseline_labels:
        raise DomainInputError(
            "Generic-ML prediction outputs do not exactly cover one labeled confirmatory split"
        )
    if (
        type(metric["candidate_accuracy"]) is not float
        or type(metric["baseline_accuracy"]) is not float
        or metric["candidate_accuracy"] != candidate_output_accuracy
        or metric["baseline_accuracy"] != baseline_output_accuracy
    ):
        raise DomainInputError(
            "Generic-ML reported accuracy differs from reference recomputation"
        )

    loaded_pretrained = observations["loaded_pretrained_resource_inventory"]
    if (
        contract.candidate_conditions.pretrained_resources.strip().casefold()
        != "none"
        or baseline_conditions.pretrained_resources.strip().casefold()
        != "none"
        or loaded_pretrained
        != {
            "schema_version": (
                _SCIENTIFIC_DOMAIN_GENERIC_ML_PRETRAINED_INVENTORY_SCHEMA
            ),
            "completeness": "EXHAUSTIVE",
            "artifact_sha256s": [],
        }
    ):
        raise DomainInputError(
            "Generic-ML v1 supports only prospectively declared and observed no-pretraining runs"
        )
    pretrained_policy = PretrainedResourcePolicyEvidence(
        resources=(),
        inventory_artifact_sha256=candidate.raw_source_record.sha256,
        contamination_status=PretrainedContaminationStatus.NOT_APPLICABLE,
        contamination_assessment_artifact_sha256=None,
    )

    robustness = observations["robustness_outputs"]
    if not isinstance(robustness, list) or len(robustness) > MAX_DOMAIN_CHECKS:
        raise DomainInputError("Generic-ML robustness results are not bounded")
    observed_robustness: dict[str, str] = {}
    for value in robustness:
        if not isinstance(value, Mapping) or set(value) != {
            "robustness_test_id",
            "artifact_sha256",
            "artifact_record_hash",
        }:
            raise DomainInputError("Generic-ML robustness result is malformed")
        test_id = value["robustness_test_id"]
        _validate_text(test_id, "Generic-ML robustness test ID")
        if test_id in observed_robustness:
            raise DomainInputError("Generic-ML robustness result is duplicated")
        output = execution_output_record(
            value["artifact_sha256"],
            value["artifact_record_hash"],
            "Generic-ML robustness output",
        )
        try:
            raw = registry.get_bytes(output.sha256)
        except (ArtifactError, ValidationError) as exc:
            raise DomainInputError(
                "Generic-ML robustness output cannot be parsed"
            ) from exc
        if (
            output.logical_type != "experiment_output.generic_ml_robustness"
            or output.schema_version
            != _SCIENTIFIC_DOMAIN_GENERIC_ML_ROBUSTNESS_ARTIFACT_SCHEMA
            or output.mime_type != "application/json"
        ):
            raise DomainInputError(
                "Generic-ML robustness output has the wrong source-owned schema"
            )
        _validate_trusted_kernel_generic_ml_robustness_bytes(
            raw,
            execution_run_id=candidate.plan.execution_run_id,
            robustness_test_id=test_id,
            candidate_model_artifact_sha256=candidate_model_record.sha256,
            evaluator_artifact_sha256=evaluator_record.sha256,
            confirmatory_split_authority_artifact_sha256=(
                confirmatory_record.sha256
            ),
        )
        observed_robustness[test_id] = output.sha256
    if set(observed_robustness) != set(contract.robustness_tests):
        raise DomainInputError(
            "Generic-ML robustness outputs are not exhaustive under the contract"
        )
    return _ScientificDomainVerifiedEvidence(
        evidence=GenericMLValidityEvidence(
            examples=examples,
            preprocessing_fit_splits=preprocessing_splits,
            benchmark_version=dataset_authority.version,
            pretrained_contamination_checked=True,
            seed_policy_frozen=(spec.seeds == contract.seed_reporting.seeds),
            checkpoint_selection_split=checkpoint_split,
            metric_implementation_verified=True,
            hyperparameter_budget_equivalent=(
                candidate_conditions.tuning_trials
                == baseline_conditions.tuning_trials
            ),
            compute_budget_equivalent=(
                candidate_conditions.compute_budget
                == baseline_conditions.compute_budget
            ),
            robustness_evaluated=True,
            generalization_claimed=False,
            external_validation_performed=None,
            early_stopping_policy=early_stopping,
            augmentation_policy=augmentation,
            model_resource_comparison=model_comparison,
            pretrained_resource_policy=pretrained_policy,
        ),
        semantic_source_records=tuple(semantic_records),
    )


def _verify_trusted_kernel_generic_ml_observations(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    candidate: _ScientificDomainSourceCandidate,
    _trust_root_reader: Callable[..., tuple[bytes, str]] = (
        _require_generic_ml_observation_trust_root
    ),
    _derive: Callable[
        [ArtifactRegistry, EventLedger, _ScientificDomainSourceCandidate],
        object,
    ] = _derive_trusted_kernel_generic_ml_observations,
) -> object:
    key, trust_root_id = _trust_root_reader(
        registry,
        expected_trust_root_id=candidate.plan.trust_root_id,
    )
    raw_value = candidate.raw_source_payload
    attestation = raw_value["source_authentication"]
    signed_source = {
        key_name: raw_value[key_name]
        for key_name in raw_value
        if key_name != "source_authentication"
    }
    metadata_claim = {
        "logical_type": candidate.raw_source_record.logical_type,
        "origin": candidate.raw_source_record.origin,
        "creator_role": candidate.raw_source_record.creator_role.value,
        "creation_command": list(candidate.raw_source_record.creation_command),
        "parent_artifacts": list(candidate.raw_source_record.parent_artifacts),
        "schema_version": candidate.raw_source_record.schema_version,
        "mime_type": candidate.raw_source_record.mime_type,
        "validation_result": candidate.raw_source_record.validation_result,
        "frozen": candidate.raw_source_record.frozen,
        "created_at": candidate.raw_source_record.created_at,
    }
    signed_payload = {
        "domain_separator": (
            "SCIENTIST_ONE_TRUSTED_KERNEL_GENERIC_ML_OBSERVATIONS_V1"
        ),
        "attestation_identity": {
            "attestation_schema": attestation["attestation_schema"],
            "verifier_id": attestation["verifier_id"],
            "trust_root_id": attestation["trust_root_id"],
            "key_id": attestation["key_id"],
        },
        "source": signed_source,
        "artifact_metadata": metadata_claim,
    }
    signed_bytes = canonical_json_bytes(signed_payload)
    expected_tag = hmac.new(key, signed_bytes, hashlib.sha256).hexdigest()
    if (
        trust_root_id != candidate.plan.trust_root_id
        or attestation["attestation_schema"]
        != SCIENTIFIC_DOMAIN_GENERIC_ML_ATTESTATION_SCHEMA
        or attestation["verifier_id"]
        != SCIENTIFIC_DOMAIN_GENERIC_ML_VERIFIER_ID
        or attestation["trust_root_id"] != trust_root_id
        or attestation["key_id"] != trust_root_id
        or attestation["signed_payload_sha256"]
        != sha256_bytes(signed_bytes)
        or not isinstance(attestation["authentication_tag"], str)
        or not _SHA256_RE.fullmatch(attestation["authentication_tag"])
        or not hmac.compare_digest(
            attestation["authentication_tag"],
            expected_tag,
        )
    ):
        raise DomainInputError(
            "trusted-kernel Generic-ML observation authentication failed"
        )
    return _derive(
        registry,
        ledger,
        candidate,
    )


def _verify_trusted_kernel_generic_ml_observations_v2(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    candidate: _ScientificDomainSourceCandidate,
    _trust_root_reader: Callable[..., tuple[bytes, str]] = (
        _require_generic_ml_observation_trust_root
    ),
    _derive: Callable[..., object] = derive_generic_ml_projection_facts,
) -> _ScientificDomainVerifiedEvidence:
    """Authenticate v2, then derive every fact from source-owned bytes."""

    key, trust_root_id = _trust_root_reader(
        registry,
        expected_trust_root_id=candidate.plan.trust_root_id,
    )
    raw_value = candidate.raw_source_payload
    attestation = raw_value["source_authentication"]
    signed_source = {
        key_name: raw_value[key_name]
        for key_name in raw_value
        if key_name != "source_authentication"
    }
    metadata_claim = {
        "logical_type": candidate.raw_source_record.logical_type,
        "origin": candidate.raw_source_record.origin,
        "creator_role": candidate.raw_source_record.creator_role.value,
        "creation_command": list(candidate.raw_source_record.creation_command),
        "parent_artifacts": list(candidate.raw_source_record.parent_artifacts),
        "schema_version": candidate.raw_source_record.schema_version,
        "mime_type": candidate.raw_source_record.mime_type,
        "validation_result": candidate.raw_source_record.validation_result,
        "frozen": candidate.raw_source_record.frozen,
        "created_at": candidate.raw_source_record.created_at,
    }
    signed_payload = {
        "domain_separator": GENERIC_ML_ATTESTATION_DOMAIN_SEPARATOR,
        "attestation_identity": {
            "attestation_schema": attestation["attestation_schema"],
            "verifier_id": attestation["verifier_id"],
            "trust_root_id": attestation["trust_root_id"],
            "key_id": attestation["key_id"],
        },
        "source": signed_source,
        "artifact_metadata": metadata_claim,
    }
    signed_bytes = canonical_json_bytes(signed_payload)
    expected_tag = hmac.new(key, signed_bytes, hashlib.sha256).hexdigest()
    if (
        trust_root_id != candidate.plan.trust_root_id
        or attestation["attestation_schema"] != GENERIC_ML_ATTESTATION_SCHEMA
        or attestation["verifier_id"] != GENERIC_ML_VERIFIER_ID
        or attestation["trust_root_id"] != trust_root_id
        or attestation["key_id"] != trust_root_id
        or attestation["signed_payload_sha256"] != sha256_bytes(signed_bytes)
        or not isinstance(attestation["authentication_tag"], str)
        or not _SHA256_RE.fullmatch(attestation["authentication_tag"])
        or not hmac.compare_digest(
            attestation["authentication_tag"],
            expected_tag,
        )
    ):
        raise DomainInputError(
            "trusted-kernel Generic-ML v2 observation authentication failed"
        )
    facts = _derive(registry, ledger, candidate)
    return _ScientificDomainVerifiedEvidence(
        evidence=facts.evidence,
        semantic_source_records=facts.semantic_source_records,
    )


_SCIENTIFIC_DOMAIN_SOURCE_VERIFIERS: Mapping[
    tuple[DomainKind, str, str], _ScientificDomainSourceVerifier
] = MappingProxyType(
    {
        (
            DomainKind.GENERIC_ML,
            SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID,
            SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
        ): _verify_trusted_kernel_generic_ml_observations,
        (
            DomainKind.GENERIC_ML,
            SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID,
            GENERIC_ML_OBSERVATIONS_FORMAT_VERSION,
        ): _verify_trusted_kernel_generic_ml_observations_v2,
    }
)
del _verify_trusted_kernel_generic_ml_observations
del _verify_trusted_kernel_generic_ml_observations_v2
del _require_generic_ml_observation_trust_root
del _read_generic_ml_observation_trust_root


def _load_scientific_domain_source_candidate(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    plan_artifact_sha256: str,
    raw_source_artifact_sha256: str,
    scientific_execution_authority_artifact_sha256: str,
    canonical_run_artifact_sha256: str,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
    _verifiers: Mapping[
        tuple[DomainKind, str, str], _ScientificDomainSourceVerifier
    ] = _SCIENTIFIC_DOMAIN_SOURCE_VERIFIERS,
) -> tuple[_ScientificDomainSourceCandidate, _ScientificDomainSourceVerifier]:
    plan = require_scientific_domain_evidence_plan(
        registry,
        ledger,
        plan_artifact_sha256=plan_artifact_sha256,
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
    )
    profile = _scientific_domain_profile(
        plan.domain,
        plan.source_format_id,
        plan.source_format_version,
    )
    verifier = _verifiers.get(profile.key)
    if verifier is None:
        raise ScientificDomainAdmissionUnavailable(
            profile.unavailable_status,
            profile.reason_code,
            profile.reason,
        )
    try:
        from .experiments import require_scientific_execution_authority
        from .research_state import require_current_scientific_execution_run

        execution_authority = require_scientific_execution_authority(
            registry,
            ledger,
            authority_artifact_sha256=(
                scientific_execution_authority_artifact_sha256
            ),
            expected_ledger_run_id=expected_run_id,
            expected_execution_run_id=plan.execution_run_id,
        )
        execution_record = registry.get_metadata(
            scientific_execution_authority_artifact_sha256
        )
        run_binding = require_current_scientific_execution_run(
            registry,
            ledger,
            run_id=expected_run_id,
            run_state_artifact_sha256=canonical_run_artifact_sha256,
            expected_execution_run_id=plan.execution_run_id,
        )
        canonical_run_record = registry.get_metadata(
            canonical_run_artifact_sha256
        )
    except ScientificDomainAdmissionUnavailable:
        raise
    except Exception as exc:
        raise DomainInputError(
            "scientific domain source execution or canonical Run failed replay"
        ) from exc
    run_metadata = thaw_json(run_binding.research_object.metadata)
    if (
        execution_authority.frozen_run_spec_artifact_sha256
        != plan.frozen_run_spec_artifact_sha256
        or execution_authority.ledger_event_index <= plan.ledger_event_index
        or run_binding.materialization_event_index
        <= execution_authority.ledger_event_index
        or run_metadata.get(
            "scientific_execution_authority_artifact_sha256"
        )
        != scientific_execution_authority_artifact_sha256
        or canonical_run_record.sha256 != run_binding.artifact_sha256
        or canonical_run_record.record_hash != run_binding.artifact_record_hash
    ):
        raise DomainInputError(
            "scientific domain source run closure or event order was substituted"
        )
    raw_record, raw_value = _canonical_registry_object(
        registry,
        raw_source_artifact_sha256,
        "scientific domain raw source",
    )
    current_events = ledger.validate(raise_on_error=True).events
    run_event_index = run_binding.materialization_event_index
    if (
        run_event_index >= len(current_events)
        or current_events[run_event_index].event_id
        != run_binding.materialization_event_id
        or current_events[run_event_index].event_hash
        != run_binding.materialization_event_hash
    ):
        raise DomainInputError(
            "scientific domain canonical Run event is substituted"
        )
    _require_scientific_domain_causal_time(
        earlier=current_events[run_event_index].timestamp,
        earlier_label="canonical Run materialization event time",
        later=raw_record.created_at,
        later_label="scientific domain raw-source created time",
        failure="scientific domain raw-source time precedes its canonical Run",
    )
    required = {
        "schema_version",
        "run_id",
        "domain",
        "object_id",
        "task_id",
        "source_format_id",
        "source_format_version",
        "plan_artifact_sha256",
        "plan_record_hash",
        "execution_run_id",
        "scientific_execution_authority_artifact_sha256",
        "scientific_execution_authority_record_hash",
        "canonical_run_artifact_sha256",
        "canonical_run_record_hash",
        "canonical_run_content_hash",
        "issued_at",
        "observations_sha256",
        "domain_observations",
        "source_authentication",
    }
    attestation_keys = {
        "attestation_schema",
        "verifier_id",
        "trust_root_id",
        "key_id",
        "signed_payload_sha256",
        "authentication_tag",
    }
    attestation = raw_value.get("source_authentication")
    observations = raw_value.get("domain_observations")
    if (
        set(raw_value) != required
        or not isinstance(attestation, Mapping)
        or set(attestation) != attestation_keys
        or not isinstance(observations, Mapping)
        or not observations
        or raw_record.logical_type
        != _scientific_domain_raw_logical_type(
            expected_domain,
            plan.source_format_id,
        )
        or raw_record.schema_version != SCIENTIFIC_DOMAIN_RAW_SOURCE_SCHEMA_VERSION
        or raw_record.mime_type != "application/json"
        or raw_record.origin
        != _scientific_domain_raw_origin(
            expected_domain,
            expected_object_id,
            plan.source_format_id,
        )
        or raw_record.creator_role is not Role.EVIDENCE_CURATOR
        or raw_record.creation_command
        != ("scientist-one", "ingest-scientific-domain-raw-source")
        or raw_record.validation_result != "PASS"
        or raw_record.frozen is not True
        or raw_record.parent_artifacts
        != (
            plan.plan_artifact_sha256,
            scientific_execution_authority_artifact_sha256,
            canonical_run_artifact_sha256,
        )
        or raw_value["schema_version"]
        != SCIENTIFIC_DOMAIN_RAW_SOURCE_SCHEMA_VERSION
        or raw_value["run_id"] != expected_run_id
        or raw_value["domain"] != expected_domain.value
        or raw_value["object_id"] != expected_object_id
        or raw_value["task_id"] != expected_task_id
        or raw_value["source_format_id"] != plan.source_format_id
        or raw_value["source_format_version"] != plan.source_format_version
        or raw_value["plan_artifact_sha256"] != plan.plan_artifact_sha256
        or raw_value["plan_record_hash"] != plan.plan_record_hash
        or raw_value["execution_run_id"] != plan.execution_run_id
        or raw_value["scientific_execution_authority_artifact_sha256"]
        != scientific_execution_authority_artifact_sha256
        or raw_value["scientific_execution_authority_record_hash"]
        != execution_record.record_hash
        or raw_value["canonical_run_artifact_sha256"]
        != canonical_run_artifact_sha256
        or raw_value["canonical_run_record_hash"]
        != canonical_run_record.record_hash
        or raw_value["canonical_run_content_hash"]
        != run_binding.research_object.content_hash
        or raw_value["issued_at"] != raw_record.created_at
        or raw_value["observations_sha256"]
        != sha256_bytes(canonical_json_bytes(observations))
        or attestation.get("attestation_schema") != plan.attestation_schema
        or attestation.get("verifier_id") != plan.verifier_id
        or attestation.get("trust_root_id") != plan.trust_root_id
        or attestation.get("key_id") != plan.trust_root_id
    ):
        raise DomainInputError(
            "scientific domain raw source is not the exact authenticated run-bound format"
        )
    for key in (
        "attestation_schema",
        "verifier_id",
        "trust_root_id",
        "key_id",
        "authentication_tag",
    ):
        _validate_text(attestation[key], f"scientific domain {key}")
    _validate_sha256(
        attestation["signed_payload_sha256"],
        "scientific domain signed payload",
    )
    signed_source = {
        key: raw_value[key]
        for key in required
        if key != "source_authentication"
    }
    metadata_claim = {
        "logical_type": raw_record.logical_type,
        "origin": raw_record.origin,
        "creator_role": raw_record.creator_role.value,
        "creation_command": list(raw_record.creation_command),
        "parent_artifacts": list(raw_record.parent_artifacts),
        "schema_version": raw_record.schema_version,
        "mime_type": raw_record.mime_type,
        "validation_result": raw_record.validation_result,
        "frozen": raw_record.frozen,
        "created_at": raw_record.created_at,
    }
    signed_payload = {
        "domain_separator": profile.domain_separator,
        "attestation_identity": {
            "attestation_schema": attestation["attestation_schema"],
            "verifier_id": attestation["verifier_id"],
            "trust_root_id": attestation["trust_root_id"],
            "key_id": attestation["key_id"],
        },
        "source": signed_source,
        "artifact_metadata": metadata_claim,
    }
    if attestation["signed_payload_sha256"] != sha256_bytes(
        canonical_json_bytes(signed_payload)
    ):
        raise DomainInputError(
            "scientific domain source authentication signs different source bytes"
        )
    return (
        _ScientificDomainSourceCandidate(
            plan=plan,
            plan_record=registry.get_metadata(plan.plan_artifact_sha256),
            raw_source_record=raw_record,
            raw_source_payload=raw_value,
            canonical_run_record=canonical_run_record,
            canonical_run_binding=run_binding,
            scientific_execution_authority_record=execution_record,
            scientific_execution_authority=execution_authority,
        ),
        verifier,
    )


def _verify_scientific_domain_source_candidate(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    candidate: _ScientificDomainSourceCandidate,
    verifier: _ScientificDomainSourceVerifier,
) -> tuple[object, tuple[ArtifactRecord, ...]]:
    try:
        verified = verifier(registry, ledger, candidate)
    except ScientificDomainAdmissionUnavailable:
        raise
    except Exception as exc:
        raise DomainInputError(
            "scientific domain raw-source verifier rejected the candidate"
        ) from exc
    if not isinstance(verified, _ScientificDomainVerifiedEvidence):
        raise DomainInputError(
            "scientific domain verifier returned no typed source closure"
        )
    evidence = verified.evidence
    expected_type = _domain_evidence_type(candidate.plan.domain)
    if (
        candidate.plan.domain is DomainKind.GENERIC_ML
        and candidate.plan.source_format_id == SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID
        and candidate.plan.source_format_version == GENERIC_ML_OBSERVATIONS_FORMAT_VERSION
        and type(evidence) is GenericMLFixedModelValidityEvidence
    ):
        # The closed raw verifier has already derived this exact type from
        # complete observations and the full prospective reference-work owner.
        # Never extend fixture/default dispatch or select it from source JSON.
        expected_type = GenericMLFixedModelValidityEvidence
    if type(evidence) is not expected_type:
        raise DomainInputError(
            "scientific domain verifier returned the wrong typed evidence"
        )
    embedded_hashes = _embedded_artifact_hashes(evidence)
    authority = candidate.scientific_execution_authority
    run_binding = candidate.canonical_run_binding
    allowed_hashes = {
        candidate.plan_record.sha256,
        candidate.raw_source_record.sha256,
        candidate.canonical_run_record.sha256,
        candidate.scientific_execution_authority_record.sha256,
        candidate.plan.evaluation_contract_artifact_sha256,
        candidate.plan.dataset_authority_artifact_sha256,
        *candidate.plan.split_authority_artifact_sha256s,
        candidate.plan.frozen_run_spec_artifact_sha256,
        candidate.scientific_execution_authority.environment_artifact_sha256,
        candidate.scientific_execution_authority.output_manifest_artifact_sha256,
        *candidate.scientific_execution_authority.output_artifact_sha256s,
        *authority.source_artifact_hashes,
        *run_binding.authority_artifact_hashes,
        *(record.sha256 for record in verified.semantic_source_records),
    }
    if not set(embedded_hashes).issubset(allowed_hashes):
        raise DomainInputError(
            "scientific domain verifier evidence names authority outside the run closure"
        )
    semantic_records = verified.semantic_source_records
    if (
        not isinstance(semantic_records, tuple)
        or len(semantic_records) > MAX_DOMAIN_CHECKS
        or any(type(record) is not ArtifactRecord for record in semantic_records)
        or len({record.sha256 for record in semantic_records})
        != len(semantic_records)
    ):
        raise DomainInputError(
            "scientific domain verifier returned an invalid semantic source closure"
        )
    ordered_hashes: list[str] = []
    for digest in (
        candidate.raw_source_record.sha256,
        candidate.plan_record.sha256,
        candidate.canonical_run_record.sha256,
        candidate.scientific_execution_authority_record.sha256,
        *(record.sha256 for record in semantic_records),
        *embedded_hashes,
    ):
        if digest not in ordered_hashes:
            ordered_hashes.append(digest)
    records: list[ArtifactRecord] = []
    semantic_by_hash = {record.sha256: record for record in semantic_records}
    for digest in ordered_hashes:
        try:
            registry.verify(digest, raise_on_error=True)
            record = registry.get_metadata(digest)
        except (ArtifactError, ValidationError) as exc:
            raise DomainInputError(
                "scientific domain evidence authority cannot be reopened"
            ) from exc
        if (
            (
                digest in semantic_by_hash
                and record != semantic_by_hash[digest]
            )
            or
            record.validation_result != "PASS"
            or record.frozen is not True
            or record.creator_role is Role.HUMAN_RELEASE
        ):
            raise DomainInputError(
                "scientific domain evidence authority is not frozen PASS non-E4 evidence"
            )
        records.append(record)
    return evidence, tuple(records)


def resolve_scientific_domain_admission(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    plan_artifact_sha256: str,
    raw_source_artifact_sha256: str,
    scientific_execution_authority_artifact_sha256: str,
    canonical_run_artifact_sha256: str,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
) -> ScientificDomainAdmissionResolution:
    """Verify one raw candidate without issuing scientific source authority."""

    try:
        candidate, verifier = _load_scientific_domain_source_candidate(
            registry,
            ledger,
            plan_artifact_sha256=plan_artifact_sha256,
            raw_source_artifact_sha256=raw_source_artifact_sha256,
            scientific_execution_authority_artifact_sha256=(
                scientific_execution_authority_artifact_sha256
            ),
            canonical_run_artifact_sha256=canonical_run_artifact_sha256,
            expected_run_id=expected_run_id,
            expected_domain=expected_domain,
            expected_object_id=expected_object_id,
            expected_task_id=expected_task_id,
        )
        evidence, _records = _verify_scientific_domain_source_candidate(
            registry,
            ledger,
            candidate,
            verifier,
        )
    except ScientificDomainAdmissionUnavailable as exc:
        return ScientificDomainAdmissionResolution(
            status=exc.status,
            reason_code=exc.reason_code,
            reason=exc.reason,
            plan_artifact_sha256=plan_artifact_sha256,
        )
    return ScientificDomainAdmissionResolution(
        status=ScientificDomainAdmissionStatus.VERIFIED,
        reason_code="SCIENTIFIC_DOMAIN_SOURCE_VERIFIED",
        reason="the exact prospective plan, run closure, and raw source verified",
        plan_artifact_sha256=candidate.plan.plan_artifact_sha256,
        source_artifact_sha256=candidate.raw_source_record.sha256,
        evidence=evidence,
    )


def _scientific_domain_source_event_id(source_artifact_sha256: str) -> str:
    _validate_sha256(source_artifact_sha256, "scientific domain source")
    return f"evt-domain-source-{source_artifact_sha256[:32]}"


def _scientific_domain_source_event_metadata(
    payload: Mapping[str, object],
    record: ArtifactRecord,
) -> Mapping[str, object]:
    return {
        "scientific_domain_evidence_source": {
            "schema_version": _SCIENTIFIC_DOMAIN_SOURCE_EVENT_SCHEMA,
            "kind": "SCIENTIFIC_DOMAIN_EVIDENCE_SOURCE_VERIFIED",
            "source_artifact_sha256": record.sha256,
            "source_record_hash": str(record.record_hash),
            "source": dict(payload),
        }
    }


def _scientific_domain_source_payload(
    candidate: _ScientificDomainSourceCandidate,
    evidence: object,
    parent_records: tuple[ArtifactRecord, ...],
) -> Mapping[str, object]:
    encoded_evidence = _encode_domain_value(evidence)
    return {
        "schema_version": SCIENTIFIC_DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION,
        "run_id": candidate.plan.run_id,
        "domain": candidate.plan.domain.value,
        "object_id": candidate.plan.object_id,
        "task_id": candidate.plan.task_id,
        "scope": DomainEvidenceScope.SCIENTIFIC_EVIDENCE.value,
        "limitations": [],
        "plan_artifact_sha256": candidate.plan.plan_artifact_sha256,
        "plan_record_hash": candidate.plan.plan_record_hash,
        "raw_source_artifact_sha256": candidate.raw_source_record.sha256,
        "raw_source_record_hash": str(
            candidate.raw_source_record.record_hash
        ),
        "scientific_execution_authority_artifact_sha256": (
            candidate.scientific_execution_authority_record.sha256
        ),
        "scientific_execution_authority_record_hash": str(
            candidate.scientific_execution_authority_record.record_hash
        ),
        "canonical_run_artifact_sha256": candidate.canonical_run_record.sha256,
        "canonical_run_record_hash": str(
            candidate.canonical_run_record.record_hash
        ),
        "canonical_run_content_hash": (
            candidate.canonical_run_binding.research_object.content_hash
        ),
        "source_format_id": candidate.plan.source_format_id,
        "source_format_version": candidate.plan.source_format_version,
        "evidence_type": type(evidence).__name__,
        "evidence_payload_sha256": sha256_bytes(
            canonical_json_bytes(encoded_evidence)
        ),
        "evidence": encoded_evidence,
        "supporting_artifact_sha256s": [
            record.sha256 for record in parent_records
        ],
        "supporting_artifact_record_hashes": [
            str(record.record_hash) for record in parent_records
        ],
    }


def _scientific_domain_source_slot_records(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
    *,
    plan_artifact_sha256: str,
) -> tuple[ArtifactRecord, ...]:
    matches: list[ArtifactRecord] = []
    for record in records:
        if not record.logical_type.startswith("domain_evidence_source."):
            continue
        try:
            value = safe_json_loads(registry.get_bytes(record.sha256))
        except Exception as exc:
            raise DomainInputError(
                "scientific domain source slot contains an unreadable artifact"
            ) from exc
        if (
            isinstance(value, Mapping)
            and value.get("schema_version")
            == SCIENTIFIC_DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION
            and value.get("plan_artifact_sha256") == plan_artifact_sha256
        ):
            matches.append(record)
    return tuple(matches)


def register_scientific_domain_evidence_source(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    plan_artifact_sha256: str,
    raw_source_artifact_sha256: str,
    scientific_execution_authority_artifact_sha256: str,
    canonical_run_artifact_sha256: str,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
) -> ArtifactRecord:
    """Issue evidence derived only by the closed production verifier."""

    candidate, verifier = _load_scientific_domain_source_candidate(
        registry,
        ledger,
        plan_artifact_sha256=plan_artifact_sha256,
        raw_source_artifact_sha256=raw_source_artifact_sha256,
        scientific_execution_authority_artifact_sha256=(
            scientific_execution_authority_artifact_sha256
        ),
        canonical_run_artifact_sha256=canonical_run_artifact_sha256,
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
    )
    evidence, parent_records = _verify_scientific_domain_source_candidate(
        registry,
        ledger,
        candidate,
        verifier,
    )
    payload = _scientific_domain_source_payload(
        candidate,
        evidence,
        parent_records,
    )
    registry_result, _ledger_result = _require_scientific_domain_runtime(
        registry,
        ledger,
        run_id=expected_run_id,
    )
    slot_records = _scientific_domain_source_slot_records(
        registry,
        registry_result.records,
        plan_artifact_sha256=candidate.plan.plan_artifact_sha256,
    )
    if len(slot_records) > 1:
        raise DomainInputError("scientific domain source slot is ambiguous")
    created_at = slot_records[0].created_at if slot_records else utc_now()
    _require_scientific_domain_causal_time(
        earlier=candidate.raw_source_record.created_at,
        earlier_label="scientific domain raw-source created time",
        later=created_at,
        later_label="scientific domain evidence-source created time",
        failure="scientific domain evidence source time precedes its raw source",
    )
    artifact_plan = _scientific_domain_artifact_plan(
        registry,
        payload,
        logical_type=_source_logical_type(expected_domain),
        origin=_scientific_domain_source_origin(
            expected_domain,
            expected_object_id,
        ),
        creator_role=Role.CLAIM_VERIFIER,
        creation_command=_SCIENTIFIC_DOMAIN_SOURCE_COMMAND,
        parent_artifacts=tuple(record.sha256 for record in parent_records),
        schema_version=SCIENTIFIC_DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION,
        created_at=created_at,
    )
    if slot_records and slot_records != (artifact_plan[1],):
        raise DomainInputError(
            "scientific domain source slot already binds other evidence"
        )
    event_id = _scientific_domain_source_event_id(artifact_plan[1].sha256)
    metadata = _scientific_domain_source_event_metadata(payload, artifact_plan[1])
    (
        registry_snapshot,
        ledger_snapshot,
        missing,
        event_to_append,
    ) = _preflight_scientific_domain_publication(
        registry,
        ledger,
        run_id=expected_run_id,
        plans=(artifact_plan,),
        event_id=event_id,
        event_timestamp=created_at,
        actor_role=Role.CLAIM_VERIFIER,
        event_artifact_hashes=(artifact_plan[1].sha256,),
        reason=(
            "verified the run-bound trusted-kernel domain observations under the "
            "prospectively frozen source profile"
        ),
        metadata=metadata,
        dataset_identifiers=(
            candidate.plan.dataset_authority_artifact_sha256,
        ),
        random_seeds=(),
    )
    committed = _commit_scientific_domain_publication(
        registry,
        ledger,
        plans=(artifact_plan,),
        registry_snapshot=registry_snapshot,
        ledger_snapshot=ledger_snapshot,
        missing=missing,
        event_to_append=event_to_append,
    )[0]
    _resolve_scientific_domain_source(
        registry,
        ledger,
        committed.sha256,
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
    )
    return committed


def register_domain_raw_fixture_source(
    registry: ArtifactRegistry,
    *,
    run_id: str,
    domain: DomainKind,
    object_id: str,
    task_id: str,
    source_id: str,
    payload: Mapping[str, object],
    creator_role: Role,
    parent_artifact_hashes: tuple[str, ...] = (),
) -> ArtifactRecord:
    """Wrap exact raw fixture content with immutable domain/run identity.

    The wrapper is intentionally and permanently non-evidentiary.  Its role is
    retained so a replay can distinguish protocol, collection, execution, and
    review inputs, but none of those logical roles upgrades fixture content.
    """

    if not isinstance(registry, ArtifactRegistry):
        raise DomainInputError("domain raw-source registration requires ArtifactRegistry")
    validate_identifier(run_id, "domain run ID")
    validate_identifier(object_id, "domain object ID")
    validate_identifier(task_id, "domain task ID")
    if not isinstance(domain, DomainKind):
        raise DomainInputError("domain raw-source kind must be typed")
    if not isinstance(source_id, str) or not _RAW_SOURCE_ID_RE.fullmatch(source_id):
        raise DomainInputError("domain raw-source ID is invalid")
    if not isinstance(payload, Mapping):
        raise DomainInputError("domain raw-source payload must be an object")
    if creator_role not in _DOMAIN_RAW_SOURCE_ROLES:
        raise DomainInputError("domain raw-source creator role is unsupported")
    if (
        not isinstance(parent_artifact_hashes, tuple)
        or len(parent_artifact_hashes) > 256
    ):
        raise DomainInputError("domain raw-source parents must be a bounded tuple")
    if parent_artifact_hashes:
        _validate_hash_tuple(parent_artifact_hashes, "domain raw-source parents")
    for digest in parent_artifact_hashes:
        try:
            registry.verify(digest, raise_on_error=True)
            parent = registry.get_metadata(digest)
        except (ArtifactError, ValidationError) as exc:
            raise DomainInputError("domain raw-source parent is absent or corrupt") from exc
        if (
            parent.validation_result != "PASS"
            or parent.frozen is not True
            or parent.creator_role is Role.HUMAN_RELEASE
        ):
            raise DomainInputError(
                "domain raw-source parents must be frozen PASS non-E4 records"
            )
    wrapper = {
        "schema_version": DOMAIN_RAW_FIXTURE_SCHEMA_VERSION,
        "run_id": run_id,
        "domain": domain.value,
        "object_id": object_id,
        "task_id": task_id,
        "source_id": source_id,
        "fixture": True,
        "real_workload_validation": "UNTESTED",
        "payload": dict(payload),
    }
    return registry.put_json(
        wrapper,
        logical_type=_raw_source_logical_type(domain, source_id),
        origin=_raw_source_origin(domain, object_id, source_id),
        creator_role=creator_role,
        creation_command=_DOMAIN_RAW_SOURCE_COMMAND,
        parent_artifacts=parent_artifact_hashes,
        schema_version=DOMAIN_RAW_FIXTURE_SCHEMA_VERSION,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )


def _load_supporting_record(
    registry: ArtifactRegistry,
    descriptor: object,
    *,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
) -> ArtifactRecord:
    if not isinstance(descriptor, Mapping) or set(descriptor) != {
        "artifact_sha256",
        "logical_type",
        "schema_version",
        "mime_type",
        "origin",
        "creator_role",
        "creation_command",
        "parent_artifacts",
        "validation_result",
        "frozen",
    }:
        raise DomainInputError("domain supporting-artifact descriptor is malformed")
    digest = descriptor["artifact_sha256"]
    _validate_sha256(digest, "domain supporting artifact")
    try:
        registry.verify(digest, raise_on_error=True)
        record = registry.get_metadata(digest)
        raw = registry.get_bytes(digest)
        payload = safe_json_loads(raw)
    except (ArtifactError, UnsafeSerializationError, ValidationError) as exc:
        raise DomainInputError("domain supporting artifact is absent or corrupt") from exc
    if (
        record.validation_result != "PASS"
        or record.frozen is not True
        or record.creator_role not in _DOMAIN_RAW_SOURCE_ROLES
        or dict(descriptor) != _artifact_descriptor(record)
    ):
        raise DomainInputError(
            "domain supporting artifact metadata differs from its exact binding"
        )
    fixture_keys = {
        "schema_version",
        "run_id",
        "domain",
        "object_id",
        "task_id",
        "source_id",
        "fixture",
        "real_workload_validation",
        "payload",
    }
    source_id = payload.get("source_id") if isinstance(payload, Mapping) else None
    if (
        not isinstance(payload, Mapping)
        or set(payload) != fixture_keys
        or raw != canonical_json_bytes(payload) + b"\n"
        or record.schema_version != DOMAIN_RAW_FIXTURE_SCHEMA_VERSION
        or not isinstance(source_id, str)
        or not _RAW_SOURCE_ID_RE.fullmatch(source_id)
        or record.logical_type != _raw_source_logical_type(expected_domain, source_id)
        or record.origin != _raw_source_origin(
            expected_domain, expected_object_id, source_id
        )
        or record.creation_command != _DOMAIN_RAW_SOURCE_COMMAND
        or payload.get("schema_version") != DOMAIN_RAW_FIXTURE_SCHEMA_VERSION
        or payload.get("run_id") != expected_run_id
        or payload.get("domain") != expected_domain.value
        or payload.get("object_id") != expected_object_id
        or payload.get("task_id") != expected_task_id
        or payload.get("fixture") is not True
        or payload.get("real_workload_validation") != "UNTESTED"
        or not isinstance(payload.get("payload"), Mapping)
    ):
        raise DomainInputError(
            "domain supporting artifact is not the exact run-bound raw fixture source"
        )
    return record


def register_domain_evidence_source(
    registry: ArtifactRegistry,
    *,
    run_id: str,
    domain: DomainKind,
    object_id: str,
    task_id: str,
    evidence: object,
    supporting_artifact_hashes: tuple[str, ...],
    scope: DomainEvidenceScope = DomainEvidenceScope.NON_EVIDENTIARY_FIXTURE,
) -> ArtifactRecord:
    """Freeze one typed input source without granting scientific authority.

    This bounded API intentionally supports only technical fixtures.  A future
    scientific scope requires domain-specific raw-source policies that can
    recompute every material judgment; it cannot be enabled by a caller flag.
    """

    if not isinstance(registry, ArtifactRegistry):
        raise DomainInputError("domain source registration requires ArtifactRegistry")
    validate_identifier(run_id, "domain run ID")
    validate_identifier(object_id, "domain object ID")
    validate_identifier(task_id, "domain task ID")
    if not isinstance(domain, DomainKind):
        raise DomainInputError("domain source kind must be typed")
    if not isinstance(scope, DomainEvidenceScope):
        raise DomainInputError("domain source scope must be typed")
    if scope is not DomainEvidenceScope.NON_EVIDENTIARY_FIXTURE:
        raise DomainInputError(
            "scientific domain evidence requires an implemented raw-source policy; "
            "caller-selected scope cannot grant authority"
        )
    expected_type = _domain_evidence_type(domain)
    if type(evidence) is not expected_type:
        raise DomainInputError("domain evidence type does not match the requested domain")
    _validate_hash_tuple(
        supporting_artifact_hashes, "domain supporting artifacts"
    )
    records: list[ArtifactRecord] = []
    for digest in supporting_artifact_hashes:
        try:
            registry.verify(digest, raise_on_error=True)
            record = registry.get_metadata(digest)
        except (ArtifactError, ValidationError) as exc:
            raise DomainInputError(
                "domain supporting artifact is absent or corrupt"
            ) from exc
        records.append(
            _load_supporting_record(
                registry,
                _artifact_descriptor(record),
                expected_run_id=run_id,
                expected_domain=domain,
                expected_object_id=object_id,
                expected_task_id=task_id,
            )
        )
    embedded_hashes = _embedded_artifact_hashes(evidence)
    if not set(embedded_hashes).issubset(set(supporting_artifact_hashes)):
        raise DomainInputError(
            "typed domain evidence references an undeclared supporting artifact"
        )
    encoded_evidence = _encode_domain_value(evidence)
    limitations = _fixture_limitations(domain)
    payload = {
        "schema_version": DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION,
        "run_id": run_id,
        "domain": domain.value,
        "object_id": object_id,
        "task_id": task_id,
        "scope": scope.value,
        "limitations": [value.value for value in limitations],
        "evidence_type": expected_type.__name__,
        "evidence_payload_sha256": sha256_bytes(
            canonical_json_bytes(encoded_evidence)
        ),
        "evidence": encoded_evidence,
        "supporting_sources": [_artifact_descriptor(record) for record in records],
    }
    return registry.put_json(
        payload,
        logical_type=_source_logical_type(domain),
        origin=_source_origin(domain, object_id),
        creator_role=Role.EVIDENCE_CURATOR,
        creation_command=_DOMAIN_SOURCE_COMMAND,
        parent_artifacts=supporting_artifact_hashes,
        schema_version=DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )


def _resolve_scientific_domain_source(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    source_artifact_sha256: str,
    *,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
) -> _ResolvedDomainSource:
    """Freshly replay the source verifier and exact ledger admission."""

    registry_result, ledger_result = _require_scientific_domain_runtime(
        registry,
        ledger,
        run_id=expected_run_id,
    )
    record, value = _canonical_registry_object(
        registry,
        source_artifact_sha256,
        "scientific domain evidence source",
    )
    required = {
        "schema_version",
        "run_id",
        "domain",
        "object_id",
        "task_id",
        "scope",
        "limitations",
        "plan_artifact_sha256",
        "plan_record_hash",
        "raw_source_artifact_sha256",
        "raw_source_record_hash",
        "scientific_execution_authority_artifact_sha256",
        "scientific_execution_authority_record_hash",
        "canonical_run_artifact_sha256",
        "canonical_run_record_hash",
        "canonical_run_content_hash",
        "source_format_id",
        "source_format_version",
        "evidence_type",
        "evidence_payload_sha256",
        "evidence",
        "supporting_artifact_sha256s",
        "supporting_artifact_record_hashes",
    }
    if set(value) != required:
        raise DomainInputError("scientific domain evidence source schema is not exact")
    if (
        record.logical_type != _source_logical_type(expected_domain)
        or record.schema_version
        != SCIENTIFIC_DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION
        or record.mime_type != "application/json"
        or record.origin
        != _scientific_domain_source_origin(expected_domain, expected_object_id)
        or record.creator_role is not Role.CLAIM_VERIFIER
        or record.creation_command != _SCIENTIFIC_DOMAIN_SOURCE_COMMAND
        or record.validation_result != "PASS"
        or record.frozen is not True
        or value["schema_version"]
        != SCIENTIFIC_DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION
        or value["run_id"] != expected_run_id
        or value["domain"] != expected_domain.value
        or value["object_id"] != expected_object_id
        or value["task_id"] != expected_task_id
        or value["scope"] != DomainEvidenceScope.SCIENTIFIC_EVIDENCE.value
        or value["limitations"] != []
        or not isinstance(value["supporting_artifact_sha256s"], list)
        or not isinstance(value["supporting_artifact_record_hashes"], list)
    ):
        raise DomainInputError("scientific domain evidence source is substituted")
    candidate, verifier = _load_scientific_domain_source_candidate(
        registry,
        ledger,
        plan_artifact_sha256=str(value["plan_artifact_sha256"]),
        raw_source_artifact_sha256=str(value["raw_source_artifact_sha256"]),
        scientific_execution_authority_artifact_sha256=str(
            value["scientific_execution_authority_artifact_sha256"]
        ),
        canonical_run_artifact_sha256=str(
            value["canonical_run_artifact_sha256"]
        ),
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
    )
    evidence, parent_records = _verify_scientific_domain_source_candidate(
        registry,
        ledger,
        candidate,
        verifier,
    )
    _require_scientific_domain_causal_time(
        earlier=candidate.raw_source_record.created_at,
        earlier_label="scientific domain raw-source created time",
        later=record.created_at,
        later_label="scientific domain evidence-source created time",
        failure="scientific domain evidence source time precedes its raw source",
    )
    expected_payload = _scientific_domain_source_payload(
        candidate,
        evidence,
        parent_records,
    )
    if (
        dict(value) != expected_payload
        or record.parent_artifacts
        != tuple(item.sha256 for item in parent_records)
        or value["supporting_artifact_record_hashes"]
        != [str(item.record_hash) for item in parent_records]
    ):
        raise DomainInputError(
            "scientific domain evidence differs from fresh source verification"
        )
    slot_records = _scientific_domain_source_slot_records(
        registry,
        registry_result.records,
        plan_artifact_sha256=candidate.plan.plan_artifact_sha256,
    )
    if slot_records != (record,):
        raise DomainInputError("scientific domain evidence source slot is ambiguous")
    event_id = _scientific_domain_source_event_id(record.sha256)
    matches = tuple(
        (index, event)
        for index, event in enumerate(ledger_result.events)
        if event.event_id == event_id
    )
    if len(matches) != 1 or matches[0][0] == 0:
        raise DomainInputError(
            "scientific domain evidence source lacks one exact ledger event"
        )
    event_index, event = matches[0]
    prior = ledger_result.events[event_index - 1]
    expected_event = LedgerEvent.create(
        run_id=expected_run_id,
        actor_role=Role.CLAIM_VERIFIER,
        state_before=prior.requested_state_after,
        requested_state_after=prior.requested_state_after,
        artifact_hashes=(record.sha256,),
        code_version=prior.code_version,
        configuration_hash=prior.configuration_hash,
        dataset_identifiers=(
            candidate.plan.dataset_authority_artifact_sha256,
        ),
        random_seeds=(),
        reason=(
            "verified the run-bound trusted-kernel domain observations under the "
            "prospectively frozen source profile"
        ),
        prior_event_hash=prior.event_hash,
        event_id=event_id,
        timestamp=record.created_at,
        event_type="CHECKPOINT",
        metadata=_scientific_domain_source_event_metadata(value, record),
    )
    if (
        event != expected_event
        or event_index
        <= max(
            candidate.plan.ledger_event_index,
            candidate.scientific_execution_authority.ledger_event_index,
            candidate.canonical_run_binding.materialization_event_index,
        )
        or any(
            later.event_type == "CORRECTION"
            and later.supersedes_event_id == event.event_id
            for later in ledger_result.events[event_index + 1 :]
        )
    ):
        raise DomainInputError(
            "scientific domain evidence source event is stale or substituted"
        )
    return _ResolvedDomainSource(
        record=record,
        run_id=expected_run_id,
        domain=expected_domain,
        object_id=expected_object_id,
        task_id=expected_task_id,
        scope=DomainEvidenceScope.SCIENTIFIC_EVIDENCE,
        limitations=(),
        supporting_artifact_hashes=tuple(
            item.sha256 for item in parent_records
        ),
        evidence_payload_sha256=str(value["evidence_payload_sha256"]),
        evidence=evidence,
    )


def require_scientific_domain_evidence_source(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    source_artifact_sha256: str,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
) -> ScientificDomainEvidenceSourceAuthority:
    """Freshly replay one scientific source without traversing assessment state."""

    resolved = _resolve_scientific_domain_source(
        registry,
        ledger,
        source_artifact_sha256,
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
    )
    source_record, value = _canonical_registry_object(
        registry,
        source_artifact_sha256,
        "scientific domain evidence source",
    )
    plan = require_scientific_domain_evidence_plan(
        registry,
        ledger,
        plan_artifact_sha256=str(value["plan_artifact_sha256"]),
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
    )
    events = ledger.validate(raise_on_error=True).events
    matches = tuple(
        (index, event)
        for index, event in enumerate(events)
        if event.event_id == _scientific_domain_source_event_id(source_record.sha256)
    )
    if len(matches) != 1 or matches[0][1].event_hash is None:
        raise DomainInputError("scientific domain source publication is ambiguous")
    event_index, event = matches[0]
    return ScientificDomainEvidenceSourceAuthority(
        source_artifact_sha256=source_record.sha256,
        source_record_hash=str(source_record.record_hash),
        plan_artifact_sha256=plan.plan_artifact_sha256,
        plan_record_hash=plan.plan_record_hash,
        raw_source_artifact_sha256=str(value["raw_source_artifact_sha256"]),
        raw_source_record_hash=str(value["raw_source_record_hash"]),
        scientific_execution_authority_artifact_sha256=str(
            value["scientific_execution_authority_artifact_sha256"]
        ),
        scientific_execution_authority_record_hash=str(
            value["scientific_execution_authority_record_hash"]
        ),
        canonical_run_artifact_sha256=str(
            value["canonical_run_artifact_sha256"]
        ),
        canonical_run_record_hash=str(value["canonical_run_record_hash"]),
        canonical_run_content_hash=str(value["canonical_run_content_hash"]),
        run_id=resolved.run_id,
        execution_run_id=plan.execution_run_id,
        domain=resolved.domain,
        object_id=resolved.object_id,
        task_id=resolved.task_id,
        source_format_id=plan.source_format_id,
        source_format_version=plan.source_format_version,
        evaluation_contract_artifact_sha256=(
            plan.evaluation_contract_artifact_sha256
        ),
        evaluation_contract_record_hash=plan.evaluation_contract_record_hash,
        dataset_authority_artifact_sha256=(
            plan.dataset_authority_artifact_sha256
        ),
        dataset_authority_record_hash=plan.dataset_authority_record_hash,
        split_authority_artifact_sha256s=(
            plan.split_authority_artifact_sha256s
        ),
        split_authority_record_hashes=plan.split_authority_record_hashes,
        frozen_run_spec_artifact_sha256=plan.frozen_run_spec_artifact_sha256,
        frozen_run_spec_record_hash=plan.frozen_run_spec_record_hash,
        evidence_payload_sha256=resolved.evidence_payload_sha256,
        evidence=resolved.evidence,
        supporting_artifact_sha256s=tuple(
            value["supporting_artifact_sha256s"]
        ),
        supporting_artifact_record_hashes=tuple(
            value["supporting_artifact_record_hashes"]
        ),
        source_event_id=event.event_id,
        source_event_hash=str(event.event_hash),
        source_event_index=event_index,
    )


def _resolve_domain_source(
    registry: ArtifactRegistry,
    source_artifact_sha256: str,
    *,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
    ledger: EventLedger | None = None,
) -> _ResolvedDomainSource:
    record, value = _canonical_registry_object(
        registry, source_artifact_sha256, "domain evidence source"
    )
    if value.get("schema_version") == (
        SCIENTIFIC_DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION
    ):
        if ledger is None:
            raise DomainInputError(
                "scientific domain source replay requires its exact ledger"
            )
        return _resolve_scientific_domain_source(
            registry,
            ledger,
            source_artifact_sha256,
            expected_run_id=expected_run_id,
            expected_domain=expected_domain,
            expected_object_id=expected_object_id,
            expected_task_id=expected_task_id,
        )
    required = {
        "schema_version",
        "run_id",
        "domain",
        "object_id",
        "task_id",
        "scope",
        "limitations",
        "evidence_type",
        "evidence_payload_sha256",
        "evidence",
        "supporting_sources",
    }
    if set(value) != required:
        raise DomainInputError("domain evidence source schema is incomplete or unknown")
    if (
        record.logical_type != _source_logical_type(expected_domain)
        or record.schema_version != DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION
        or record.mime_type != "application/json"
        or record.creator_role is not Role.EVIDENCE_CURATOR
        or record.creation_command != _DOMAIN_SOURCE_COMMAND
        or record.validation_result != "PASS"
        or record.frozen is not True
        or record.origin != _source_origin(expected_domain, expected_object_id)
    ):
        raise DomainInputError("artifact is not the expected typed domain evidence source")
    if (
        value["schema_version"] != DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION
        or value["run_id"] != expected_run_id
        or value["domain"] != expected_domain.value
        or value["object_id"] != expected_object_id
        or value["task_id"] != expected_task_id
    ):
        raise DomainInputError("domain evidence source identity was substituted")
    try:
        scope = DomainEvidenceScope(value["scope"])
    except (TypeError, ValueError) as exc:
        raise DomainInputError("domain evidence source scope is unknown") from exc
    # The v1 source schema is permanently fixture-only.  Scientific admission
    # uses the disjoint v2 schema and its paired-ledger replay path.
    if scope is not DomainEvidenceScope.NON_EVIDENTIARY_FIXTURE:
        raise DomainInputError(
            "scientific domain evidence has no implemented raw-source resolver"
        )
    expected_limitations = _fixture_limitations(expected_domain)
    if value["limitations"] != [item.value for item in expected_limitations]:
        raise DomainInputError("domain evidence limitations were weakened or reordered")
    if not isinstance(value["supporting_sources"], list) or not value[
        "supporting_sources"
    ]:
        raise DomainInputError("domain evidence source must bind supporting artifacts")
    if len(value["supporting_sources"]) > 256:
        raise DomainInputError("domain evidence source has too many supporting artifacts")
    supporting_records = tuple(
        _load_supporting_record(
            registry,
            descriptor,
            expected_run_id=expected_run_id,
            expected_domain=expected_domain,
            expected_object_id=expected_object_id,
            expected_task_id=expected_task_id,
        )
        for descriptor in value["supporting_sources"]
    )
    supporting_hashes = tuple(item.sha256 for item in supporting_records)
    if (
        len(set(supporting_hashes)) != len(supporting_hashes)
        or record.parent_artifacts != supporting_hashes
    ):
        raise DomainInputError(
            "domain evidence source parent order differs from its source bindings"
        )
    expected_type = _domain_evidence_type(expected_domain)
    if value["evidence_type"] != expected_type.__name__:
        raise DomainInputError("domain evidence source names the wrong evidence type")
    evidence_payload_sha256 = value["evidence_payload_sha256"]
    _validate_sha256(evidence_payload_sha256, "domain evidence payload")
    if evidence_payload_sha256 != sha256_bytes(
        canonical_json_bytes(value["evidence"])
    ):
        raise DomainInputError("domain evidence payload hash does not match its content")
    evidence = _decode_domain_value(value["evidence"])
    if (
        type(evidence) is not expected_type
        or _encode_domain_value(evidence) != value["evidence"]
    ):
        raise DomainInputError("domain evidence did not round-trip to its exact typed form")
    if not set(_embedded_artifact_hashes(evidence)).issubset(set(supporting_hashes)):
        raise DomainInputError(
            "rehydrated domain evidence references an undeclared supporting artifact"
        )
    return _ResolvedDomainSource(
        record=record,
        run_id=expected_run_id,
        domain=expected_domain,
        object_id=expected_object_id,
        task_id=expected_task_id,
        scope=scope,
        limitations=expected_limitations,
        supporting_artifact_hashes=supporting_hashes,
        evidence_payload_sha256=evidence_payload_sha256,
        evidence=evidence,
    )


def _scientific_domain_manifest_origin(
    domain: DomainKind,
    object_id: str,
) -> str:
    return f"source-verified {domain.value} evidence manifest for {object_id}"


def _scientific_domain_receipt_origin(
    domain: DomainKind,
    object_id: str,
) -> str:
    return f"freshly replayed scientific {domain.value} validity for {object_id}"


def _scientific_domain_validity_event_id(receipt_sha256: str) -> str:
    _validate_sha256(receipt_sha256, "scientific domain validity receipt")
    return f"evt-domain-validity-{receipt_sha256[:32]}"


def _scientific_domain_validity_event_metadata(
    *,
    manifest: ArtifactRecord,
    receipt: ArtifactRecord,
    source_artifact_sha256: str,
    outcome: DomainValidityOutcome,
) -> Mapping[str, object]:
    return {
        "scientific_domain_validity": {
            "schema_version": _SCIENTIFIC_DOMAIN_VALIDITY_EVENT_SCHEMA,
            "kind": "SCIENTIFIC_DOMAIN_VALIDITY_REPLAYED",
            "manifest_artifact_sha256": manifest.sha256,
            "manifest_record_hash": str(manifest.record_hash),
            "receipt_artifact_sha256": receipt.sha256,
            "receipt_record_hash": str(receipt.record_hash),
            "source_artifact_sha256": source_artifact_sha256,
            "outcome": outcome.to_dict(),
        }
    }


def _scientific_domain_materialization_slot_records(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
    *,
    source_artifact_sha256: str,
) -> tuple[tuple[ArtifactRecord, ...], tuple[ArtifactRecord, ...]]:
    manifests: list[ArtifactRecord] = []
    receipts: list[ArtifactRecord] = []
    for record in records:
        if record.schema_version not in {
            SCIENTIFIC_DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION,
            SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION,
            SCIENTIFIC_DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION_V3,
            SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION_V3,
        }:
            continue
        try:
            value = safe_json_loads(registry.get_bytes(record.sha256))
        except Exception as exc:
            raise DomainInputError(
                "scientific domain materialization slot is unreadable"
            ) from exc
        if not isinstance(value, Mapping):
            raise DomainInputError(
                "scientific domain materialization slot is malformed"
            )
        if record.schema_version in {
            SCIENTIFIC_DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION,
            SCIENTIFIC_DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION_V3,
        }:
            if value.get("source_artifact_sha256") == source_artifact_sha256:
                manifests.append(record)
        elif value.get("source_artifact_sha256") == source_artifact_sha256:
            receipts.append(record)
    return tuple(manifests), tuple(receipts)


def _scientific_domain_validity_event_metadata_v3(
    *,
    manifest: ArtifactRecord,
    receipt: ArtifactRecord,
    source_artifact_sha256: str,
    projection_artifact_sha256: str,
    projection_record_hash: str,
    outcome: DomainValidityOutcome,
) -> Mapping[str, object]:
    return {
        "scientific_domain_validity": {
            "schema_version": _SCIENTIFIC_DOMAIN_VALIDITY_EVENT_SCHEMA_V2,
            "kind": "SCIENTIFIC_DOMAIN_VALIDITY_REPLAYED_FROM_PROJECTION",
            "manifest_artifact_sha256": manifest.sha256,
            "manifest_record_hash": str(manifest.record_hash),
            "receipt_artifact_sha256": receipt.sha256,
            "receipt_record_hash": str(receipt.record_hash),
            "source_artifact_sha256": source_artifact_sha256,
            "projection_artifact_sha256": projection_artifact_sha256,
            "projection_record_hash": projection_record_hash,
            "outcome": outcome.to_dict(),
        }
    }


def _scientific_domain_v3_plans(
    registry: ArtifactRegistry,
    *,
    source: _ResolvedDomainSource,
    source_record: ArtifactRecord,
    source_value: Mapping[str, object],
    projection: object,
    source_event: LedgerEvent,
    source_event_index: int,
    created_at: str,
) -> tuple[
    tuple[bytes, ArtifactRecord],
    tuple[bytes, ArtifactRecord],
    DomainValidityOutcome,
]:
    # All callers supply the freshly replayed source, never a decoded payload
    # alone. Its distinct evidence type keeps old adapter2 receipt bytes fixed.
    adapter = (
        GenericMLFixedModelAdapter()
        if source.domain is DomainKind.GENERIC_ML
        and type(source.evidence) is GenericMLFixedModelValidityEvidence
        else get_domain_adapter(source.domain)
    )
    outcome = adapter.evaluate(source.evidence)
    manifest_payload = {
        "schema_version": SCIENTIFIC_DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION_V3,
        "run_id": source.run_id,
        "domain": source.domain.value,
        "object_id": source.object_id,
        "task_id": source.task_id,
        "scope": DomainEvidenceScope.SCIENTIFIC_EVIDENCE.value,
        "limitations": [],
        "source_artifact_sha256": source_record.sha256,
        "source_record_hash": str(source_record.record_hash),
        "plan_artifact_sha256": source_value["plan_artifact_sha256"],
        "raw_source_artifact_sha256": source_value[
            "raw_source_artifact_sha256"
        ],
        "scientific_execution_authority_artifact_sha256": source_value[
            "scientific_execution_authority_artifact_sha256"
        ],
        "canonical_run_artifact_sha256": source_value[
            "canonical_run_artifact_sha256"
        ],
        "source_event_id": source_event.event_id,
        "source_event_hash": source_event.event_hash,
        "source_event_index": source_event_index,
        "projection_artifact_sha256": projection.projection_artifact_sha256,
        "projection_record_hash": projection.projection_record_hash,
        "projection_event_id": projection.ledger_event_id,
        "projection_event_hash": projection.ledger_event_hash,
        "projection_event_index": projection.ledger_event_index,
        "domain_consumed_output_artifact_sha256s": list(
            projection.domain_consumed_output_artifact_sha256s
        ),
        "domain_consumed_output_record_hashes": list(
            projection.domain_consumed_output_record_hashes
        ),
        "evidence_payload_sha256": source.evidence_payload_sha256,
        "evidence_type": type(source.evidence).__name__,
    }
    manifest_plan = _scientific_domain_artifact_plan(
        registry,
        manifest_payload,
        logical_type=_manifest_logical_type(source.domain),
        origin=_scientific_domain_manifest_origin(source.domain, source.object_id),
        creator_role=Role.EVIDENCE_CURATOR,
        creation_command=_SCIENTIFIC_DOMAIN_MATERIALIZATION_COMMAND,
        parent_artifacts=(
            source_record.sha256,
            projection.projection_artifact_sha256,
        ),
        schema_version=SCIENTIFIC_DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION_V3,
        created_at=created_at,
    )
    receipt_payload = {
        "schema_version": SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION_V3,
        "run_id": source.run_id,
        "domain": source.domain.value,
        "object_id": source.object_id,
        "task_id": source.task_id,
        "scope": DomainEvidenceScope.SCIENTIFIC_EVIDENCE.value,
        "limitations": [],
        "manifest_artifact_sha256": manifest_plan[1].sha256,
        "manifest_record_hash": str(manifest_plan[1].record_hash),
        "source_artifact_sha256": source_record.sha256,
        "source_record_hash": str(source_record.record_hash),
        "projection_artifact_sha256": projection.projection_artifact_sha256,
        "projection_record_hash": projection.projection_record_hash,
        "adapter_version": outcome.adapter_version,
        "outcome": outcome.to_dict(),
    }
    receipt_plan = _scientific_domain_artifact_plan(
        registry,
        receipt_payload,
        logical_type=_receipt_logical_type(source.domain),
        origin=_scientific_domain_receipt_origin(source.domain, source.object_id),
        creator_role=Role.SCIENTIFIC_REVIEWER,
        creation_command=_SCIENTIFIC_DOMAIN_MATERIALIZATION_COMMAND,
        parent_artifacts=(
            manifest_plan[1].sha256,
            source_record.sha256,
            projection.projection_artifact_sha256,
        ),
        schema_version=SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION_V3,
        created_at=created_at,
    )
    return manifest_plan, receipt_plan, outcome


def _materialize_scientific_domain_validity_v3(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    source: _ResolvedDomainSource,
) -> ArtifactRecord:
    from .experiments import require_scientific_execution_authority
    from .generic_ml_projection import (
        require_current_generic_ml_paired_metric_projection_authority,
    )

    registry_result, ledger_result = _require_scientific_domain_runtime(
        registry,
        ledger,
        run_id=source.run_id,
    )
    source_record, source_value = _canonical_registry_object(
        registry,
        source.record.sha256,
        "scientific domain evidence source",
    )
    source_authority = require_scientific_domain_evidence_source(
        registry,
        ledger,
        source_artifact_sha256=source_record.sha256,
        expected_run_id=source.run_id,
        expected_domain=source.domain,
        expected_object_id=source.object_id,
        expected_task_id=source.task_id,
    )
    execution = require_scientific_execution_authority(
        registry,
        ledger,
        authority_artifact_sha256=(
            source_authority.scientific_execution_authority_artifact_sha256
        ),
        expected_ledger_run_id=source.run_id,
        expected_execution_run_id=source_authority.execution_run_id,
    )
    projection = require_current_generic_ml_paired_metric_projection_authority(
        registry,
        ledger,
        scientific_domain_evidence_source_artifact_sha256=source_record.sha256,
        expected_ledger_run_id=source.run_id,
        expected_execution_run_id=source_authority.execution_run_id,
        expected_contract_artifact_sha256=(
            source_authority.evaluation_contract_artifact_sha256
        ),
        expected_output_manifest_artifact_sha256=(
            execution.output_manifest_artifact_sha256
        ),
    )
    source_events = tuple(
        (index, event)
        for index, event in enumerate(ledger_result.events)
        if event.event_id == source_authority.source_event_id
        and event.event_hash == source_authority.source_event_hash
    )
    if len(source_events) != 1:
        raise DomainInputError("scientific domain v3 source event is ambiguous")
    source_event_index, source_event = source_events[0]
    manifests, receipts = _scientific_domain_materialization_slot_records(
        registry,
        registry_result.records,
        source_artifact_sha256=source_record.sha256,
    )
    if len(manifests) > 1 or len(receipts) > 1:
        raise DomainInputError("scientific domain v3 validity slot is ambiguous")
    timestamps = {record.created_at for record in (*manifests, *receipts)}
    if len(timestamps) > 1:
        raise DomainInputError("scientific domain v3 orphan timestamps disagree")
    created_at = next(iter(timestamps), utc_now())
    _require_scientific_domain_causal_time(
        earlier=registry.get_metadata(
            projection.projection_artifact_sha256
        ).created_at,
        earlier_label="Generic-ML projection created time",
        later=created_at,
        later_label="scientific domain v3 validity created time",
        failure="scientific domain v3 validity time precedes its projection",
    )
    manifest_plan, receipt_plan, outcome = _scientific_domain_v3_plans(
        registry,
        source=source,
        source_record=source_record,
        source_value=source_value,
        projection=projection,
        source_event=source_event,
        source_event_index=source_event_index,
        created_at=created_at,
    )
    if manifests and manifests != (manifest_plan[1],):
        raise DomainInputError("scientific domain v3 manifest slot already differs")
    if receipts and receipts != (receipt_plan[1],):
        raise DomainInputError("scientific domain v3 receipt slot already differs")
    event_id = _scientific_domain_validity_event_id(receipt_plan[1].sha256)
    metadata = _scientific_domain_validity_event_metadata_v3(
        manifest=manifest_plan[1],
        receipt=receipt_plan[1],
        source_artifact_sha256=source_record.sha256,
        projection_artifact_sha256=projection.projection_artifact_sha256,
        projection_record_hash=projection.projection_record_hash,
        outcome=outcome,
    )
    registry_snapshot, ledger_snapshot, missing, event_to_append = (
        _preflight_scientific_domain_publication(
            registry,
            ledger,
            run_id=source.run_id,
            plans=(manifest_plan, receipt_plan),
            event_id=event_id,
            event_timestamp=created_at,
            actor_role=Role.SCIENTIFIC_REVIEWER,
            event_artifact_hashes=(
                manifest_plan[1].sha256,
                receipt_plan[1].sha256,
            ),
            reason=(
                "replayed the exact Generic-ML source and paired projection "
                "through the deterministic domain adapter"
            ),
            metadata=metadata,
            dataset_identifiers=(source_authority.dataset_authority_artifact_sha256,),
            random_seeds=projection.seed_order,
        )
    )
    receipt = _commit_scientific_domain_publication(
        registry,
        ledger,
        plans=(manifest_plan, receipt_plan),
        registry_snapshot=registry_snapshot,
        ledger_snapshot=ledger_snapshot,
        missing=missing,
        event_to_append=event_to_append,
    )[1]
    _resolve_scientific_domain_validity_v3(
        registry,
        ledger,
        receipt.sha256,
        expected_run_id=source.run_id,
        expected_domain=source.domain,
        expected_object_id=source.object_id,
        expected_task_id=source.task_id,
    )
    return receipt


def _materialize_scientific_domain_validity(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    source: _ResolvedDomainSource,
) -> ArtifactRecord:
    registry_result, ledger_result = _require_scientific_domain_runtime(
        registry,
        ledger,
        run_id=source.run_id,
    )
    source_record, source_value = _canonical_registry_object(
        registry,
        source.record.sha256,
        "scientific domain evidence source",
    )
    if (
        source.domain is DomainKind.GENERIC_ML
        and source_value.get("source_format_version")
        == GENERIC_ML_OBSERVATIONS_FORMAT_VERSION
    ):
        return _materialize_scientific_domain_validity_v3(
            registry,
            ledger,
            source=source,
        )
    source_event_id = _scientific_domain_source_event_id(source_record.sha256)
    source_events = tuple(
        (index, event)
        for index, event in enumerate(ledger_result.events)
        if event.event_id == source_event_id
    )
    if len(source_events) != 1 or source_events[0][1].event_hash is None:
        raise DomainInputError(
            "scientific domain source event is absent or ambiguous"
        )
    source_event_index, source_event = source_events[0]
    outcome = get_domain_adapter(source.domain).evaluate(source.evidence)
    manifest_payload = {
        "schema_version": SCIENTIFIC_DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION,
        "run_id": source.run_id,
        "domain": source.domain.value,
        "object_id": source.object_id,
        "task_id": source.task_id,
        "scope": DomainEvidenceScope.SCIENTIFIC_EVIDENCE.value,
        "limitations": [],
        "source_artifact_sha256": source_record.sha256,
        "source_record_hash": str(source_record.record_hash),
        "plan_artifact_sha256": source_value["plan_artifact_sha256"],
        "raw_source_artifact_sha256": source_value[
            "raw_source_artifact_sha256"
        ],
        "scientific_execution_authority_artifact_sha256": source_value[
            "scientific_execution_authority_artifact_sha256"
        ],
        "canonical_run_artifact_sha256": source_value[
            "canonical_run_artifact_sha256"
        ],
        "source_event_id": source_event.event_id,
        "source_event_hash": source_event.event_hash,
        "source_event_index": source_event_index,
        "evidence_payload_sha256": source.evidence_payload_sha256,
        "evidence_type": type(source.evidence).__name__,
    }
    manifests, receipts = _scientific_domain_materialization_slot_records(
        registry,
        registry_result.records,
        source_artifact_sha256=source.record.sha256,
    )
    if len(manifests) > 1 or len(receipts) > 1:
        raise DomainInputError("scientific domain validity slot is ambiguous")
    existing_timestamps = {
        record.created_at for record in (*manifests, *receipts)
    }
    if len(existing_timestamps) > 1:
        raise DomainInputError(
            "scientific domain validity orphan timestamps disagree"
        )
    created_at = next(iter(existing_timestamps), utc_now())
    manifest_plan = _scientific_domain_artifact_plan(
        registry,
        manifest_payload,
        logical_type=_manifest_logical_type(source.domain),
        origin=_scientific_domain_manifest_origin(source.domain, source.object_id),
        creator_role=Role.EVIDENCE_CURATOR,
        creation_command=_SCIENTIFIC_DOMAIN_MATERIALIZATION_COMMAND,
        parent_artifacts=(source.record.sha256,),
        schema_version=SCIENTIFIC_DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION,
        created_at=created_at,
    )
    receipt_payload = {
        "schema_version": SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION,
        "run_id": source.run_id,
        "domain": source.domain.value,
        "object_id": source.object_id,
        "task_id": source.task_id,
        "scope": DomainEvidenceScope.SCIENTIFIC_EVIDENCE.value,
        "limitations": [],
        "manifest_artifact_sha256": manifest_plan[1].sha256,
        "manifest_record_hash": str(manifest_plan[1].record_hash),
        "source_artifact_sha256": source.record.sha256,
        "source_record_hash": str(source.record.record_hash),
        "adapter_version": outcome.adapter_version,
        "outcome": outcome.to_dict(),
    }
    receipt_plan = _scientific_domain_artifact_plan(
        registry,
        receipt_payload,
        logical_type=_receipt_logical_type(source.domain),
        origin=_scientific_domain_receipt_origin(source.domain, source.object_id),
        creator_role=Role.SCIENTIFIC_REVIEWER,
        creation_command=_SCIENTIFIC_DOMAIN_MATERIALIZATION_COMMAND,
        parent_artifacts=(manifest_plan[1].sha256, source.record.sha256),
        schema_version=SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION,
        created_at=created_at,
    )
    if manifests and manifests != (manifest_plan[1],):
        raise DomainInputError(
            "scientific domain validity manifest slot already differs"
        )
    if receipts and receipts != (receipt_plan[1],):
        raise DomainInputError(
            "scientific domain validity receipt slot already differs"
        )
    event_id = _scientific_domain_validity_event_id(receipt_plan[1].sha256)
    metadata = _scientific_domain_validity_event_metadata(
        manifest=manifest_plan[1],
        receipt=receipt_plan[1],
        source_artifact_sha256=source.record.sha256,
        outcome=outcome,
    )
    (
        registry_snapshot,
        ledger_snapshot,
        missing,
        event_to_append,
    ) = _preflight_scientific_domain_publication(
        registry,
        ledger,
        run_id=source.run_id,
        plans=(manifest_plan, receipt_plan),
        event_id=event_id,
        event_timestamp=created_at,
        actor_role=Role.SCIENTIFIC_REVIEWER,
        event_artifact_hashes=(
            manifest_plan[1].sha256,
            receipt_plan[1].sha256,
        ),
        reason=(
            "replayed the exact source-verified domain evidence through the "
            "deterministic domain adapter"
        ),
        metadata=metadata,
        dataset_identifiers=(
            str(source_value["canonical_run_artifact_sha256"]),
        ),
        random_seeds=(),
    )
    committed = _commit_scientific_domain_publication(
        registry,
        ledger,
        plans=(manifest_plan, receipt_plan),
        registry_snapshot=registry_snapshot,
        ledger_snapshot=ledger_snapshot,
        missing=missing,
        event_to_append=event_to_append,
    )
    receipt = committed[1]
    _resolve_scientific_domain_validity(
        registry,
        ledger,
        receipt.sha256,
        expected_run_id=source.run_id,
        expected_domain=source.domain,
        expected_object_id=source.object_id,
        expected_task_id=source.task_id,
    )
    return receipt


def _resolve_scientific_domain_validity_v3(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    receipt_artifact_sha256: str,
    *,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
) -> ResolvedDomainValidity:
    from .experiments import require_scientific_execution_authority
    from .generic_ml_projection import (
        require_generic_ml_paired_metric_projection_authority,
    )

    registry_result, ledger_result = _require_scientific_domain_runtime(
        registry,
        ledger,
        run_id=expected_run_id,
    )
    receipt_record, receipt = _canonical_registry_object(
        registry,
        receipt_artifact_sha256,
        "scientific domain v3 validity receipt",
    )
    required_receipt = {
        "schema_version",
        "run_id",
        "domain",
        "object_id",
        "task_id",
        "scope",
        "limitations",
        "manifest_artifact_sha256",
        "manifest_record_hash",
        "source_artifact_sha256",
        "source_record_hash",
        "projection_artifact_sha256",
        "projection_record_hash",
        "adapter_version",
        "outcome",
    }
    if set(receipt) != required_receipt:
        raise DomainInputError("scientific domain v3 receipt schema is not exact")
    for name in (
        "manifest_artifact_sha256",
        "manifest_record_hash",
        "source_artifact_sha256",
        "source_record_hash",
        "projection_artifact_sha256",
        "projection_record_hash",
    ):
        _validate_sha256(receipt[name], f"scientific domain v3 {name}")
    if (
        receipt_record.schema_version
        != SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION_V3
        or receipt_record.logical_type != _receipt_logical_type(expected_domain)
        or receipt_record.mime_type != "application/json"
        or receipt_record.origin
        != _scientific_domain_receipt_origin(expected_domain, expected_object_id)
        or receipt_record.creator_role is not Role.SCIENTIFIC_REVIEWER
        or receipt_record.creation_command
        != _SCIENTIFIC_DOMAIN_MATERIALIZATION_COMMAND
        or receipt_record.validation_result != "PASS"
        or receipt_record.frozen is not True
        or receipt["schema_version"]
        != SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION_V3
        or receipt["run_id"] != expected_run_id
        or receipt["domain"] != expected_domain.value
        or receipt["object_id"] != expected_object_id
        or receipt["task_id"] != expected_task_id
        or receipt["scope"] != DomainEvidenceScope.SCIENTIFIC_EVIDENCE.value
        or receipt["limitations"] != []
    ):
        raise DomainInputError("scientific domain v3 receipt identity is substituted")
    source = _resolve_scientific_domain_source(
        registry,
        ledger,
        str(receipt["source_artifact_sha256"]),
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
    )
    source_record, source_value = _canonical_registry_object(
        registry,
        source.record.sha256,
        "scientific domain v3 evidence source",
    )
    source_authority = require_scientific_domain_evidence_source(
        registry,
        ledger,
        source_artifact_sha256=source_record.sha256,
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
    )
    execution = require_scientific_execution_authority(
        registry,
        ledger,
        authority_artifact_sha256=(
            source_authority.scientific_execution_authority_artifact_sha256
        ),
        expected_ledger_run_id=expected_run_id,
        expected_execution_run_id=source_authority.execution_run_id,
    )
    projection = require_generic_ml_paired_metric_projection_authority(
        registry,
        ledger,
        projection_artifact_sha256=str(receipt["projection_artifact_sha256"]),
        expected_ledger_run_id=expected_run_id,
        expected_execution_run_id=source_authority.execution_run_id,
        expected_domain_evidence_source_artifact_sha256=source_record.sha256,
        expected_contract_artifact_sha256=(
            source_authority.evaluation_contract_artifact_sha256
        ),
        expected_output_manifest_artifact_sha256=(
            execution.output_manifest_artifact_sha256
        ),
    )
    source_events = tuple(
        (index, event)
        for index, event in enumerate(ledger_result.events)
        if event.event_id == source_authority.source_event_id
        and event.event_hash == source_authority.source_event_hash
    )
    if len(source_events) != 1:
        raise DomainInputError("scientific domain v3 source event is ambiguous")
    source_event_index, source_event = source_events[0]
    manifest_record, _manifest = _canonical_registry_object(
        registry,
        str(receipt["manifest_artifact_sha256"]),
        "scientific domain v3 evidence manifest",
    )
    manifest_plan, receipt_plan, outcome = _scientific_domain_v3_plans(
        registry,
        source=source,
        source_record=source_record,
        source_value=source_value,
        projection=projection,
        source_event=source_event,
        source_event_index=source_event_index,
        created_at=receipt_record.created_at,
    )
    if (
        manifest_record != manifest_plan[1]
        or receipt_record != receipt_plan[1]
        or registry.get_bytes(manifest_record.sha256) != manifest_plan[0]
        or registry.get_bytes(receipt_record.sha256) != receipt_plan[0]
        or receipt_record.parent_artifacts
        != (
            manifest_record.sha256,
            source_record.sha256,
            projection.projection_artifact_sha256,
        )
    ):
        raise DomainInputError(
            "scientific domain v3 artifacts differ from fresh projection replay"
        )
    manifests, receipts = _scientific_domain_materialization_slot_records(
        registry,
        registry_result.records,
        source_artifact_sha256=source_record.sha256,
    )
    if manifests != (manifest_record,) or receipts != (receipt_record,):
        raise DomainInputError("scientific domain v3 validity slot is ambiguous")
    matches = tuple(
        (index, event)
        for index, event in enumerate(ledger_result.events)
        if event.event_id == _scientific_domain_validity_event_id(receipt_record.sha256)
    )
    if len(matches) != 1 or matches[0][0] == 0:
        raise DomainInputError("scientific domain v3 validity event is ambiguous")
    event_index, event = matches[0]
    prior = ledger_result.events[event_index - 1]
    expected_event = LedgerEvent.create(
        run_id=expected_run_id,
        actor_role=Role.SCIENTIFIC_REVIEWER,
        state_before=prior.requested_state_after,
        requested_state_after=prior.requested_state_after,
        artifact_hashes=(manifest_record.sha256, receipt_record.sha256),
        code_version=prior.code_version,
        configuration_hash=prior.configuration_hash,
        dataset_identifiers=(source_authority.dataset_authority_artifact_sha256,),
        random_seeds=projection.seed_order,
        reason=(
            "replayed the exact Generic-ML source and paired projection "
            "through the deterministic domain adapter"
        ),
        prior_event_hash=prior.event_hash,
        event_id=_scientific_domain_validity_event_id(receipt_record.sha256),
        timestamp=receipt_record.created_at,
        event_type="CHECKPOINT",
        metadata=_scientific_domain_validity_event_metadata_v3(
            manifest=manifest_record,
            receipt=receipt_record,
            source_artifact_sha256=source_record.sha256,
            projection_artifact_sha256=projection.projection_artifact_sha256,
            projection_record_hash=projection.projection_record_hash,
            outcome=outcome,
        ),
    )
    if (
        event != expected_event
        or event_index <= max(source_event_index, projection.ledger_event_index)
        or manifest_record.created_at != receipt_record.created_at
        or receipt["source_record_hash"] != source_record.record_hash
        or receipt["projection_record_hash"] != projection.projection_record_hash
        or receipt["adapter_version"] != outcome.adapter_version
        or receipt["outcome"] != outcome.to_dict()
        or any(
            later.event_type == "CORRECTION"
            and later.supersedes_event_id == event.event_id
            for later in ledger_result.events[event_index + 1 :]
        )
    ):
        raise DomainInputError("scientific domain v3 validity is stale or substituted")
    source_hashes = tuple(
        dict.fromkeys(
            (
                source_record.sha256,
                *source.supporting_artifact_hashes,
                projection.projection_artifact_sha256,
                *projection.paired_projection_artifact_sha256s,
            )
        )
    )
    return ResolvedDomainValidity(
        receipt_artifact_sha256=receipt_record.sha256,
        manifest_artifact_sha256=manifest_record.sha256,
        source_artifact_hashes=source_hashes,
        run_id=expected_run_id,
        domain=expected_domain,
        object_id=expected_object_id,
        task_id=expected_task_id,
        scope=DomainEvidenceScope.SCIENTIFIC_EVIDENCE,
        limitations=(),
        evidence=source.evidence,
        outcome=outcome,
        projection_artifact_sha256=projection.projection_artifact_sha256,
    )


def _resolve_scientific_domain_validity(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    receipt_artifact_sha256: str,
    *,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
) -> ResolvedDomainValidity:
    registry_result, ledger_result = _require_scientific_domain_runtime(
        registry,
        ledger,
        run_id=expected_run_id,
    )
    receipt_record, receipt = _canonical_registry_object(
        registry,
        receipt_artifact_sha256,
        "scientific domain validity receipt",
    )
    receipt_required = {
        "schema_version",
        "run_id",
        "domain",
        "object_id",
        "task_id",
        "scope",
        "limitations",
        "manifest_artifact_sha256",
        "manifest_record_hash",
        "source_artifact_sha256",
        "source_record_hash",
        "adapter_version",
        "outcome",
    }
    if set(receipt) != receipt_required:
        raise DomainInputError("scientific domain receipt schema is not exact")
    manifest_hash = receipt["manifest_artifact_sha256"]
    source_hash = receipt["source_artifact_sha256"]
    _validate_sha256(manifest_hash, "scientific domain evidence manifest")
    _validate_sha256(source_hash, "scientific domain evidence source")
    if (
        receipt_record.logical_type != _receipt_logical_type(expected_domain)
        or receipt_record.schema_version
        != SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION
        or receipt_record.mime_type != "application/json"
        or receipt_record.origin
        != _scientific_domain_receipt_origin(
            expected_domain,
            expected_object_id,
        )
        or receipt_record.creator_role is not Role.SCIENTIFIC_REVIEWER
        or receipt_record.creation_command
        != _SCIENTIFIC_DOMAIN_MATERIALIZATION_COMMAND
        or receipt_record.validation_result != "PASS"
        or receipt_record.frozen is not True
        or receipt_record.parent_artifacts != (manifest_hash, source_hash)
        or receipt["schema_version"]
        != SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION
        or receipt["run_id"] != expected_run_id
        or receipt["domain"] != expected_domain.value
        or receipt["object_id"] != expected_object_id
        or receipt["task_id"] != expected_task_id
        or receipt["scope"] != DomainEvidenceScope.SCIENTIFIC_EVIDENCE.value
        or receipt["limitations"] != []
    ):
        raise DomainInputError("scientific domain receipt identity is substituted")
    manifest_record, manifest = _canonical_registry_object(
        registry,
        manifest_hash,
        "scientific domain evidence manifest",
    )
    manifest_required = {
        "schema_version",
        "run_id",
        "domain",
        "object_id",
        "task_id",
        "scope",
        "limitations",
        "source_artifact_sha256",
        "source_record_hash",
        "plan_artifact_sha256",
        "raw_source_artifact_sha256",
        "scientific_execution_authority_artifact_sha256",
        "canonical_run_artifact_sha256",
        "source_event_id",
        "source_event_hash",
        "source_event_index",
        "evidence_payload_sha256",
        "evidence_type",
    }
    if set(manifest) != manifest_required:
        raise DomainInputError("scientific domain manifest schema is not exact")
    if (
        manifest_record.logical_type != _manifest_logical_type(expected_domain)
        or manifest_record.schema_version
        != SCIENTIFIC_DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION
        or manifest_record.mime_type != "application/json"
        or manifest_record.origin
        != _scientific_domain_manifest_origin(
            expected_domain,
            expected_object_id,
        )
        or manifest_record.creator_role is not Role.EVIDENCE_CURATOR
        or manifest_record.creation_command
        != _SCIENTIFIC_DOMAIN_MATERIALIZATION_COMMAND
        or manifest_record.validation_result != "PASS"
        or manifest_record.frozen is not True
        or manifest_record.parent_artifacts != (source_hash,)
        or manifest["schema_version"]
        != SCIENTIFIC_DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION
        or manifest["run_id"] != expected_run_id
        or manifest["domain"] != expected_domain.value
        or manifest["object_id"] != expected_object_id
        or manifest["task_id"] != expected_task_id
        or manifest["scope"] != DomainEvidenceScope.SCIENTIFIC_EVIDENCE.value
        or manifest["limitations"] != []
        or manifest["source_artifact_sha256"] != source_hash
        or receipt["manifest_record_hash"] != manifest_record.record_hash
    ):
        raise DomainInputError("scientific domain manifest identity is substituted")
    source = _resolve_scientific_domain_source(
        registry,
        ledger,
        source_hash,
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
    )
    source_record, source_value = _canonical_registry_object(
        registry,
        source_hash,
        "scientific domain evidence source",
    )
    outcome = get_domain_adapter(expected_domain).evaluate(source.evidence)
    source_event_id = _scientific_domain_source_event_id(source_hash)
    source_events = tuple(
        (index, candidate)
        for index, candidate in enumerate(ledger_result.events)
        if candidate.event_id == source_event_id
    )
    if len(source_events) != 1 or source_events[0][1].event_hash is None:
        raise DomainInputError(
            "scientific domain manifest source event is absent or ambiguous"
        )
    source_event_index, source_event = source_events[0]
    expected_manifest = {
        "schema_version": SCIENTIFIC_DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION,
        "run_id": expected_run_id,
        "domain": expected_domain.value,
        "object_id": expected_object_id,
        "task_id": expected_task_id,
        "scope": DomainEvidenceScope.SCIENTIFIC_EVIDENCE.value,
        "limitations": [],
        "source_artifact_sha256": source_hash,
        "source_record_hash": str(source_record.record_hash),
        "plan_artifact_sha256": source_value["plan_artifact_sha256"],
        "raw_source_artifact_sha256": source_value[
            "raw_source_artifact_sha256"
        ],
        "scientific_execution_authority_artifact_sha256": source_value[
            "scientific_execution_authority_artifact_sha256"
        ],
        "canonical_run_artifact_sha256": source_value[
            "canonical_run_artifact_sha256"
        ],
        "source_event_id": source_event.event_id,
        "source_event_hash": source_event.event_hash,
        "source_event_index": source_event_index,
        "evidence_payload_sha256": source.evidence_payload_sha256,
        "evidence_type": type(source.evidence).__name__,
    }
    if dict(manifest) != expected_manifest:
        raise DomainInputError(
            "scientific domain manifest differs from fresh source replay"
        )
    if (
        receipt["source_record_hash"] != source_record.record_hash
        or receipt["adapter_version"] != outcome.adapter_version
        or receipt["outcome"] != outcome.to_dict()
    ):
        raise DomainInputError(
            "scientific domain receipt differs from fresh adapter replay"
        )
    manifests, receipts = _scientific_domain_materialization_slot_records(
        registry,
        registry_result.records,
        source_artifact_sha256=source_hash,
    )
    if manifests != (manifest_record,) or receipts != (receipt_record,):
        raise DomainInputError("scientific domain validity slot is ambiguous")
    event_id = _scientific_domain_validity_event_id(receipt_record.sha256)
    matches = tuple(
        (index, event)
        for index, event in enumerate(ledger_result.events)
        if event.event_id == event_id
    )
    if len(matches) != 1 or matches[0][0] == 0:
        raise DomainInputError(
            "scientific domain validity lacks one exact ledger event"
        )
    event_index, event = matches[0]
    prior = ledger_result.events[event_index - 1]
    source_event_indexes = tuple(
        index
        for index, candidate in enumerate(ledger_result.events)
        if candidate.event_id == manifest["source_event_id"]
        and candidate.event_hash == manifest["source_event_hash"]
    )
    expected_event = LedgerEvent.create(
        run_id=expected_run_id,
        actor_role=Role.SCIENTIFIC_REVIEWER,
        state_before=prior.requested_state_after,
        requested_state_after=prior.requested_state_after,
        artifact_hashes=(manifest_record.sha256, receipt_record.sha256),
        code_version=prior.code_version,
        configuration_hash=prior.configuration_hash,
        dataset_identifiers=(
            str(manifest["canonical_run_artifact_sha256"]),
        ),
        random_seeds=(),
        reason=(
            "replayed the exact source-verified domain evidence through the "
            "deterministic domain adapter"
        ),
        prior_event_hash=prior.event_hash,
        event_id=event_id,
        timestamp=receipt_record.created_at,
        event_type="CHECKPOINT",
        metadata=_scientific_domain_validity_event_metadata(
            manifest=manifest_record,
            receipt=receipt_record,
            source_artifact_sha256=source_hash,
            outcome=outcome,
        ),
    )
    if (
        manifest_record.created_at != receipt_record.created_at
        or len(source_event_indexes) != 1
        or source_event_indexes[0] != manifest["source_event_index"]
        or event_index <= source_event_indexes[0]
        or event != expected_event
        or any(
            later.event_type == "CORRECTION"
            and later.supersedes_event_id == event.event_id
            for later in ledger_result.events[event_index + 1 :]
        )
    ):
        raise DomainInputError(
            "scientific domain validity event is stale or substituted"
        )
    return ResolvedDomainValidity(
        receipt_artifact_sha256=receipt_record.sha256,
        manifest_artifact_sha256=manifest_record.sha256,
        source_artifact_hashes=(
            source.record.sha256,
            *source.supporting_artifact_hashes,
        ),
        run_id=expected_run_id,
        domain=expected_domain,
        object_id=expected_object_id,
        task_id=expected_task_id,
        scope=DomainEvidenceScope.SCIENTIFIC_EVIDENCE,
        limitations=(),
        evidence=source.evidence,
        outcome=outcome,
    )


def materialize_domain_validity(
    registry: ArtifactRegistry,
    *,
    source_artifact_sha256: str,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
    ledger: EventLedger | None = None,
) -> ArtifactRecord:
    """Persist a manifest and full adapter replay from one exact typed source."""

    if not isinstance(registry, ArtifactRegistry):
        raise DomainInputError("domain materialization requires ArtifactRegistry")
    validate_identifier(expected_run_id, "expected domain run ID")
    validate_identifier(expected_object_id, "expected domain object ID")
    validate_identifier(expected_task_id, "expected domain task ID")
    if not isinstance(expected_domain, DomainKind):
        raise DomainInputError("expected domain must be typed")
    source = _resolve_domain_source(
        registry,
        source_artifact_sha256,
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
        ledger=ledger,
    )
    if source.scope is DomainEvidenceScope.SCIENTIFIC_EVIDENCE:
        if ledger is None:
            raise DomainInputError(
                "scientific domain materialization requires its exact ledger"
            )
        return _materialize_scientific_domain_validity(
            registry,
            ledger,
            source=source,
        )
    outcome = get_domain_adapter(expected_domain).evaluate(source.evidence)
    manifest_payload = {
        "schema_version": DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION,
        "run_id": source.run_id,
        "domain": source.domain.value,
        "object_id": source.object_id,
        "task_id": source.task_id,
        "scope": source.scope.value,
        "limitations": [value.value for value in source.limitations],
        "source_artifact_sha256": source.record.sha256,
        "supporting_artifact_hashes": list(source.supporting_artifact_hashes),
        "evidence_payload_sha256": source.evidence_payload_sha256,
        "evidence_type": type(source.evidence).__name__,
    }
    manifest = registry.put_json(
        manifest_payload,
        logical_type=_manifest_logical_type(expected_domain),
        origin=_manifest_origin(expected_domain, expected_object_id),
        creator_role=Role.EVIDENCE_CURATOR,
        creation_command=_DOMAIN_MANIFEST_COMMAND,
        parent_artifacts=(source.record.sha256,),
        schema_version=DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )
    source_hashes = (source.record.sha256, *source.supporting_artifact_hashes)
    receipt_payload = {
        "schema_version": DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION,
        "run_id": source.run_id,
        "domain": source.domain.value,
        "object_id": source.object_id,
        "task_id": source.task_id,
        "scope": source.scope.value,
        "limitations": [value.value for value in source.limitations],
        "manifest_artifact_sha256": manifest.sha256,
        "source_artifact_hashes": list(source_hashes),
        "adapter_version": outcome.adapter_version,
        "outcome": outcome.to_dict(),
    }
    receipt = registry.put_json(
        receipt_payload,
        logical_type=_receipt_logical_type(expected_domain),
        origin=_receipt_origin(expected_domain, expected_object_id),
        creator_role=Role.SCIENTIFIC_REVIEWER,
        creation_command=_DOMAIN_RECEIPT_COMMAND,
        parent_artifacts=(manifest.sha256, source.record.sha256),
        schema_version=DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION,
        mime_type="application/json",
        validation_result="PASS",
        frozen=True,
    )
    # Reopen after publication.  Materialization is not successful unless the
    # persisted bytes and full ancestry replay exactly.
    resolve_domain_validity(
        registry,
        receipt.sha256,
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
    )
    return receipt


def resolve_domain_validity(
    registry: ArtifactRegistry,
    receipt_artifact_sha256: str,
    *,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
    ledger: EventLedger | None = None,
) -> ResolvedDomainValidity:
    """Freshly resolve and replay one exact domain validity receipt."""

    if not isinstance(registry, ArtifactRegistry):
        raise DomainInputError("domain resolution requires ArtifactRegistry")
    validate_identifier(expected_run_id, "expected domain run ID")
    validate_identifier(expected_object_id, "expected domain object ID")
    validate_identifier(expected_task_id, "expected domain task ID")
    if not isinstance(expected_domain, DomainKind):
        raise DomainInputError("expected domain must be typed")
    receipt_record, receipt = _canonical_registry_object(
        registry, receipt_artifact_sha256, "domain validity receipt"
    )
    if receipt.get("schema_version") == (
        SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION_V3
    ):
        if ledger is None:
            raise DomainInputError(
                "scientific domain v3 validity replay requires its exact ledger"
            )
        return _resolve_scientific_domain_validity_v3(
            registry,
            ledger,
            receipt_artifact_sha256,
            expected_run_id=expected_run_id,
            expected_domain=expected_domain,
            expected_object_id=expected_object_id,
            expected_task_id=expected_task_id,
        )
    if receipt.get("schema_version") == (
        SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION
    ):
        if ledger is None:
            raise DomainInputError(
                "scientific domain validity replay requires its exact ledger"
            )
        return _resolve_scientific_domain_validity(
            registry,
            ledger,
            receipt_artifact_sha256,
            expected_run_id=expected_run_id,
            expected_domain=expected_domain,
            expected_object_id=expected_object_id,
            expected_task_id=expected_task_id,
        )
    required = {
        "schema_version",
        "run_id",
        "domain",
        "object_id",
        "task_id",
        "scope",
        "limitations",
        "manifest_artifact_sha256",
        "source_artifact_hashes",
        "adapter_version",
        "outcome",
    }
    if set(receipt) != required:
        raise DomainInputError("domain validity receipt schema is incomplete or unknown")
    if (
        receipt_record.logical_type != _receipt_logical_type(expected_domain)
        or receipt_record.schema_version != DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION
        or receipt_record.mime_type != "application/json"
        or receipt_record.creator_role is not Role.SCIENTIFIC_REVIEWER
        or receipt_record.creation_command != _DOMAIN_RECEIPT_COMMAND
        or receipt_record.validation_result != "PASS"
        or receipt_record.frozen is not True
        or receipt_record.origin != _receipt_origin(expected_domain, expected_object_id)
    ):
        raise DomainInputError("artifact is not the expected domain validity receipt")
    if (
        receipt["schema_version"] != DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION
        or receipt["run_id"] != expected_run_id
        or receipt["domain"] != expected_domain.value
        or receipt["object_id"] != expected_object_id
        or receipt["task_id"] != expected_task_id
    ):
        raise DomainInputError("domain validity receipt identity was substituted")
    manifest_hash = receipt["manifest_artifact_sha256"]
    _validate_sha256(manifest_hash, "domain evidence manifest")
    if (
        not isinstance(receipt["source_artifact_hashes"], list)
        or not receipt["source_artifact_hashes"]
        or len(receipt["source_artifact_hashes"]) > 257
    ):
        raise DomainInputError("domain validity source hashes are malformed")
    source_hashes = tuple(receipt["source_artifact_hashes"])
    _validate_hash_tuple(
        source_hashes, "domain validity source hashes", maximum=257
    )
    source_hash = source_hashes[0]
    if receipt_record.parent_artifacts != (manifest_hash, source_hash):
        raise DomainInputError("domain validity receipt parents were substituted")

    manifest_record, manifest = _canonical_registry_object(
        registry, manifest_hash, "domain evidence manifest"
    )
    manifest_required = {
        "schema_version",
        "run_id",
        "domain",
        "object_id",
        "task_id",
        "scope",
        "limitations",
        "source_artifact_sha256",
        "supporting_artifact_hashes",
        "evidence_payload_sha256",
        "evidence_type",
    }
    if set(manifest) != manifest_required:
        raise DomainInputError("domain evidence manifest schema is incomplete or unknown")
    if (
        manifest_record.logical_type != _manifest_logical_type(expected_domain)
        or manifest_record.schema_version != DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION
        or manifest_record.mime_type != "application/json"
        or manifest_record.creator_role is not Role.EVIDENCE_CURATOR
        or manifest_record.creation_command != _DOMAIN_MANIFEST_COMMAND
        or manifest_record.validation_result != "PASS"
        or manifest_record.frozen is not True
        or manifest_record.origin != _manifest_origin(expected_domain, expected_object_id)
        or manifest_record.parent_artifacts != (source_hash,)
    ):
        raise DomainInputError("artifact is not the expected domain evidence manifest")
    if (
        manifest["schema_version"] != DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION
        or manifest["run_id"] != expected_run_id
        or manifest["domain"] != expected_domain.value
        or manifest["object_id"] != expected_object_id
        or manifest["task_id"] != expected_task_id
        or manifest["source_artifact_sha256"] != source_hash
    ):
        raise DomainInputError("domain evidence manifest identity was substituted")

    source = _resolve_domain_source(
        registry,
        source_hash,
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
        ledger=ledger,
    )
    exact_limitations = [value.value for value in source.limitations]
    if (
        receipt["scope"] != source.scope.value
        or manifest["scope"] != source.scope.value
        or receipt["limitations"] != exact_limitations
        or manifest["limitations"] != exact_limitations
        or manifest["supporting_artifact_hashes"]
        != list(source.supporting_artifact_hashes)
        or manifest["evidence_payload_sha256"]
        != source.evidence_payload_sha256
        or manifest["evidence_type"] != type(source.evidence).__name__
        or source_hashes
        != (source.record.sha256, *source.supporting_artifact_hashes)
    ):
        raise DomainInputError("domain receipt, manifest, and source bindings disagree")
    outcome = get_domain_adapter(expected_domain).evaluate(source.evidence)
    if (
        receipt["adapter_version"] != outcome.adapter_version
        or receipt["outcome"] != outcome.to_dict()
    ):
        raise DomainInputError(
            "domain validity receipt differs from the freshly replayed adapter outcome"
        )
    return ResolvedDomainValidity(
        receipt_artifact_sha256=receipt_record.sha256,
        manifest_artifact_sha256=manifest_record.sha256,
        source_artifact_hashes=source_hashes,
        run_id=expected_run_id,
        domain=expected_domain,
        object_id=expected_object_id,
        task_id=expected_task_id,
        scope=source.scope,
        limitations=source.limitations,
        evidence=source.evidence,
        outcome=outcome,
    )


def require_scientific_domain_validity(
    registry: ArtifactRegistry,
    receipt_artifact_sha256: str,
    *,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
    ledger: EventLedger | None = None,
) -> ResolvedDomainValidity:
    """Require scientific PASS; current fixture receipts always fail closed."""

    resolved = resolve_domain_validity(
        registry,
        receipt_artifact_sha256,
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
        ledger=ledger,
    )
    if resolved.scope is not DomainEvidenceScope.SCIENTIFIC_EVIDENCE:
        raise DomainInputError(
            "non-evidentiary domain replay cannot authorize a scientific gate"
        )
    if resolved.outcome.status is not DomainValidityStatus.PASS:
        raise DomainInputError("domain validity did not pass")
    return resolved


def require_projection_backed_scientific_domain_validity(
    registry: ArtifactRegistry,
    receipt_artifact_sha256: str,
    *,
    expected_run_id: str,
    expected_domain: DomainKind,
    expected_object_id: str,
    expected_task_id: str,
    ledger: EventLedger,
) -> ResolvedDomainValidity:
    """Require current ground-truth projection authority, not legacy v2 custody."""

    resolved = require_scientific_domain_validity(
        registry,
        receipt_artifact_sha256,
        expected_run_id=expected_run_id,
        expected_domain=expected_domain,
        expected_object_id=expected_object_id,
        expected_task_id=expected_task_id,
        ledger=ledger,
    )
    if resolved.projection_artifact_sha256 is None:
        raise DomainInputError(
            "legacy scientific domain validity has no ground-truth metric projection"
        )
    return resolved


__all__ = [
    "DOMAIN_ADAPTERS",
    "MAX_DOMAIN_CHECKS",
    "MAX_DOMAIN_RECORDS",
    "AugmentationMode",
    "AugmentationPolicyEvidence",
    "ComparisonDisposition",
    "DomainAdapter",
    "DomainCheck",
    "DomainEvidenceScope",
    "DomainInputError",
    "DomainKind",
    "DomainValidityLimitation",
    "DomainValidityOutcome",
    "DomainValidityStatus",
    "DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION",
    "DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION",
    "DOMAIN_RAW_FIXTURE_SCHEMA_VERSION",
    "DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION",
    "EarlyStoppingPolicyEvidence",
    "GenericMLAdapter",
    "GenericMLExample",
    "GenericMLFixedModelAdapter",
    "GenericMLFixedModelValidityEvidence",
    "GenericMLValidityEvidence",
    "MLPolicyTiming",
    "MedicalAnalysisUnit",
    "MedicalClassificationSemantics",
    "MedicalClassificationTarget",
    "MedicalClinicalInterpretationEvidence",
    "MedicalClinicalUse",
    "MedicalImageRepresentation",
    "MedicalImageObservation",
    "MedicalImagingAdapter",
    "MedicalImagingValidityEvidence",
    "MedicalMetric",
    "MedicalRegistrationReference",
    "MedicalRegistrationSemantics",
    "MedicalRegistrationTransform",
    "MedicalSegmentationSemantics",
    "MedicalSegmentationTarget",
    "MedicalTask",
    "MedicalTaskSemantics",
    "MedicalThresholdBasis",
    "MedicalThresholdRelation",
    "MedicalThresholdUnit",
    "MetricDirection",
    "MetricScope",
    "ModelResourceComparisonEvidence",
    "ObjectiveDirection",
    "OperationsResearchAdapter",
    "OperationsResearchValidityEvidence",
    "OptimizationInstanceResult",
    "PretrainedContaminationStatus",
    "PretrainedResourceEvidence",
    "PretrainedResourcePolicyEvidence",
    "RecommenderInteraction",
    "RecommenderSplitStrategy",
    "RecommenderSystemsAdapter",
    "RecommenderValidityEvidence",
    "ResolvedDomainValidity",
    "SCIENTIFIC_DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION",
    "SCIENTIFIC_DOMAIN_EVIDENCE_MANIFEST_SCHEMA_VERSION_V3",
    "SCIENTIFIC_DOMAIN_EVIDENCE_PLAN_SCHEMA_VERSION",
    "SCIENTIFIC_DOMAIN_EVIDENCE_PLAN_ARTIFACT_SCHEMA_VERSION",
    "SCIENTIFIC_DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION",
    "SCIENTIFIC_DOMAIN_GENERIC_ML_ATTESTATION_SCHEMA",
    "SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID",
    "SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_VERSION",
    "SCIENTIFIC_DOMAIN_GENERIC_ML_TRUST_ROOT_BASENAME",
    "SCIENTIFIC_DOMAIN_GENERIC_ML_VERIFIER_ID",
    "SCIENTIFIC_DOMAIN_RAW_SOURCE_SCHEMA_VERSION",
    "SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION",
    "SCIENTIFIC_DOMAIN_VALIDITY_RECEIPT_SCHEMA_VERSION_V3",
    "ScientificDomainAdmissionResolution",
    "ScientificDomainAdmissionStatus",
    "ScientificDomainAdmissionUnavailable",
    "ScientificDomainEvidencePlan",
    "ScientificDomainEvidenceSourceAuthority",
    "SplitRole",
    "SystemsAdapter",
    "SystemsClaimScope",
    "SystemsMeasurement",
    "SystemsValidityEvidence",
    "TimeSeriesAdapter",
    "TimeSeriesValidityEvidence",
    "TimeSeriesWindow",
    "get_domain_adapter",
    "materialize_domain_validity",
    "register_domain_evidence_source",
    "register_domain_raw_fixture_source",
    "register_scientific_domain_evidence_plan",
    "register_scientific_domain_evidence_source",
    "require_scientific_domain_evidence_plan",
    "require_scientific_domain_evidence_source",
    "require_scientific_domain_validity",
    "require_projection_backed_scientific_domain_validity",
    "resolve_domain_validity",
    "revoke_scientific_domain_trust_root",
    "resolve_scientific_domain_admission",
    "resolve_scientific_domain_admission_profile",
]
