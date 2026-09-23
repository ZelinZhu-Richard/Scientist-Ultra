"""Closed Generic-ML prediction-to-metric projection authority.

This module deliberately supports one small, reviewed execution format.  It
derives labels from the exact Dataset bytes, predictions from integer linear
model envelopes, and per-unit correctness without accepting caller scores,
seed selections, or PASS labels.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from statistics import fmean
from typing import Mapping

from .artifacts import ArtifactError, ArtifactRecord, ArtifactRegistry
from .errors import ValidationError
from .ledger import EventLedger
from .models import thaw_json
from .roles import Role
from .security import canonical_json_bytes, safe_json_loads, sha256_bytes
from .models import utc_now


GENERIC_ML_OBSERVATIONS_FORMAT_VERSION = "2.0"
GENERIC_ML_ATTESTATION_SCHEMA = "trusted-kernel-generic-ml-hmac-sha256/v2"
GENERIC_ML_VERIFIER_ID = "scientist-one-generic-ml-observation-verifier/v2"
GENERIC_ML_ATTESTATION_DOMAIN_SEPARATOR = (
    "SCIENTIST_ONE_TRUSTED_KERNEL_GENERIC_ML_OBSERVATIONS_V2"
)
GENERIC_ML_OBSERVATIONS_SCHEMA = "trusted-kernel-generic-ml-observations/v2"
GENERIC_ML_POLICY_SCHEMA = "trusted-kernel-reference-accuracy/v2"
GENERIC_ML_DATASET_ROW_SCHEMA = (
    "scientist-one-bounded-integer-linear-classification-row/v1"
)
GENERIC_ML_MODEL_SCHEMA = "trusted-kernel-integer-linear-classifier/v2"
GENERIC_ML_PREDICTIONS_SCHEMA = "trusted-kernel-generic-ml-predictions/v2"
GENERIC_ML_ROBUSTNESS_SCHEMA = "trusted-kernel-generic-ml-robustness/v2"
# Content format IDs above deliberately remain unchanged. Artifact metadata
# has a separate <=32-character schema field; using the content IDs there
# made all four native per-seed output records impossible to construct.
GENERIC_ML_MODEL_ARTIFACT_SCHEMA = "generic-ml-model/v2"
GENERIC_ML_PREDICTIONS_ARTIFACT_SCHEMA = "generic-ml-predictions/v2"
GENERIC_ML_ROBUSTNESS_ARTIFACT_SCHEMA = "generic-ml-robustness/v2"
GENERIC_ML_PRETRAINED_INVENTORY_SCHEMA = (
    "trusted-kernel-loaded-pretrained-inventory/v2"
)
GENERIC_ML_ROBUSTNESS_TEST_ID = "duplicate-inference-consistency/v1"
GENERIC_ML_COMPARISON_SCOPE = "FROZEN_MODEL_CONFIRMATORY_INFERENCE_ONLY"
GENERIC_ML_FROZEN_MODEL_CONFIGURATION_SCHEMA = (
    "scientist-one-checked-generic-ml-frozen-model-configuration/v2"
)
GENERIC_ML_FROZEN_MODEL_DEFINITION_SCHEMA = (
    "trusted-kernel-frozen-integer-linear-classifier-definition/v1"
)
GENERIC_ML_PROJECTION_SCHEMA = "generic-ml-paired-metric-projection/v1"
GENERIC_ML_PROJECTION_AUTHORITY_SCHEMA = (
    "generic-ml-paired-metric-projection-authority/v1"
)
GENERIC_ML_PROJECTION_EVENT_SCHEMA = (
    "generic-ml-paired-metric-projection-event/v1"
)
GENERIC_ML_PROJECTION_SCHEMA_VERSION = "1.0"
GENERIC_ML_PROJECTION_LOGICAL_TYPE = "generic_ml_paired_metric_projection"
GENERIC_ML_PROJECTION_AUTHORITY_LOGICAL_TYPE = (
    "generic_ml_paired_metric_projection_authority"
)
GENERIC_ML_PROJECTION_COMMAND = (
    "scientist-one",
    "project-generic-ml-paired-metrics",
)
MAX_GENERIC_ML_SEEDS = 24
MAX_GENERIC_ML_UNITS = 10_000
MAX_GENERIC_ML_FEATURES = 1_024
MAX_GENERIC_ML_CLASSES = 1_024
MAX_GENERIC_ML_INTEGER_MAGNITUDE = 2**53 - 1
MAX_GENERIC_ML_FROZEN_MODEL_PARAMETERS = 65_536
MAX_GENERIC_ML_FROZEN_MODEL_GRID_PARAMETERS = 262_144
GENERIC_ML_REFERENCE_WORK_SCHEMA = (
    "scientist-one-integer-linear-reference-work/v1"
)
GENERIC_ML_REFERENCE_WORK_SCOPE = "FIXED_MODEL_REFERENCE_WORK_ONLY"
GENERIC_ML_REFERENCE_WORK_POLICY_SCHEMA = (
    "scientist-one-fixed-model-reference-work-policy/v1"
)
GENERIC_ML_REFERENCE_WORK_PROFILE_ID = (
    "FIXED_DENSE_INTEGER_LINEAR_MICRO_ACCURACY_V1"
)
GENERIC_ML_REFERENCE_WORK_WALL_CAP_SCOPE = "RUN_WIDE_CONTRACT_WALL_SECONDS"


class GenericMLProjectionError(ValidationError):
    """The closed Generic-ML projection cannot be derived or replayed."""


@dataclass(frozen=True, slots=True)
class GenericMLReferenceWorkPolicy:
    """An inert prospective declaration, not resource or execution authority."""

    schema_version: str = GENERIC_ML_REFERENCE_WORK_POLICY_SCHEMA
    profile_id: str = GENERIC_ML_REFERENCE_WORK_PROFILE_ID
    scope: str = GENERIC_ML_REFERENCE_WORK_SCOPE
    wall_cap_scope: str = GENERIC_ML_REFERENCE_WORK_WALL_CAP_SCOPE

    def __post_init__(self) -> None:
        for name, expected in (
            ("schema_version", GENERIC_ML_REFERENCE_WORK_POLICY_SCHEMA),
            ("profile_id", GENERIC_ML_REFERENCE_WORK_PROFILE_ID),
            ("scope", GENERIC_ML_REFERENCE_WORK_SCOPE),
            ("wall_cap_scope", GENERIC_ML_REFERENCE_WORK_WALL_CAP_SCOPE),
        ):
            value = getattr(self, name)
            if type(value) is not str or value != expected:
                raise GenericMLProjectionError(
                    "Generic-ML reference-work policy is malformed or unsupported"
                )

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "scope": self.scope,
            "wall_cap_scope": self.wall_cap_scope,
        }


def parse_generic_ml_reference_work_policy(value: object) -> GenericMLReferenceWorkPolicy:
    """Parse the exact declared scope; a present null is never absence."""

    if not isinstance(value, Mapping) or set(value) != {
        "schema_version", "profile_id", "scope", "wall_cap_scope",
    }:
        raise GenericMLProjectionError(
            "Generic-ML reference-work policy is malformed or unsupported"
        )
    return GenericMLReferenceWorkPolicy(**dict(value))


def require_generic_ml_reference_work_wall_cap(
    timeout_seconds: object,
    contract_wall_cap_seconds: object,
) -> tuple[float, float]:
    """Check a declared run-wide limit, never observed per-condition cost."""

    values: list[float] = []
    for value in (timeout_seconds, contract_wall_cap_seconds):
        if type(value) not in {int, float}:
            raise GenericMLProjectionError("reference-work wall limits require native finite scalars")
        try:
            current = float(value)
        except (OverflowError, ValueError) as exc:
            raise GenericMLProjectionError("reference-work wall limits require native finite scalars") from exc
        if not math.isfinite(current) or current <= 0:
            raise GenericMLProjectionError("reference-work wall limits require positive finite scalars")
        values.append(current)
    if timeout_seconds > contract_wall_cap_seconds:
        raise GenericMLProjectionError("reference-work run timeout exceeds the contract wall cap")
    return values[0], values[1]


@dataclass(frozen=True, slots=True)
class GenericMLReferenceWork:
    """Pure dense-linear reference arithmetic, never execution authority.

    One reference prediction computes C dot products of width F (F products
    and F-1 reduction additions), adds each bias, and performs a single
    first-maximum argmax scan with C-1 score comparisons. These are abstract
    counts, not Python/CPU/GPU instructions: predict() also initializes sum
    and scans for an index. Integer bit costs and all implementation overhead
    are outside this profile. No runtime, memory, energy, training, tuning or
    total-resource equivalence follows from equal reference counts.

    Inputs must eventually come from the complete owner-replayed frozen
    model/row/seed grid. This caller-reproducible value alone proves neither
    that provenance nor an enforced common cap. It does not open the existing
    domain resource-comparability or compute-budget gates.
    """

    unit_count: int
    seed_count: int
    class_count: int
    feature_count: int

    def __post_init__(self) -> None:
        for name, minimum, maximum in (
            ("unit_count", 1, MAX_GENERIC_ML_UNITS),
            ("seed_count", 1, MAX_GENERIC_ML_SEEDS),
            ("class_count", 2, MAX_GENERIC_ML_CLASSES),
            ("feature_count", 1, MAX_GENERIC_ML_FEATURES),
        ):
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise GenericMLProjectionError(
                    f"Generic-ML reference-work {name} is outside its exact bound"
                )
        parameters = self.class_count * (self.feature_count + 1)
        if (
            parameters > MAX_GENERIC_ML_FROZEN_MODEL_PARAMETERS
            or 2 * self.seed_count * parameters
            > MAX_GENERIC_ML_FROZEN_MODEL_GRID_PARAMETERS
        ):
            raise GenericMLProjectionError(
                "Generic-ML reference-work model grid exceeds its parameter bound"
            )

    def _counts(self, repetitions: int) -> dict[str, int]:
        predictions = self.unit_count * self.seed_count * repetitions
        scores = predictions * self.class_count
        return {
            "predictions": predictions,
            "integer_multiplications": scores * self.feature_count,
            "dot_reduction_additions": scores * (self.feature_count - 1),
            "bias_additions": scores,
            "argmax_score_comparisons": predictions * (self.class_count - 1),
        }

    def to_dict(self) -> dict[str, object]:
        # Robustness tests contain two candidate predictions for each frozen
        # seed/row. They are asymmetric overhead, not part of the common
        # primary-metric workload and not evidence of two real executions.
        return {
            "schema_version": GENERIC_ML_REFERENCE_WORK_SCHEMA,
            "scope": GENERIC_ML_REFERENCE_WORK_SCOPE,
            "unit_count": self.unit_count,
            "seed_count": self.seed_count,
            "class_count": self.class_count,
            "feature_count": self.feature_count,
            "candidate_primary_metric": self._counts(1),
            "baseline_primary_metric": self._counts(1),
            "candidate_robustness_overhead": self._counts(2),
        }


@dataclass(frozen=True, slots=True)
class GenericMLClassificationRow:
    unit_id: str
    unit_hash: str
    features: tuple[int, ...]
    label: int


@dataclass(frozen=True, slots=True)
class GenericMLLinearModel:
    seed: int
    role: str
    condition_id: str
    class_labels: tuple[int, ...]
    weights: tuple[tuple[int, ...], ...]
    bias: tuple[int, ...]
    parameter_count: int

    def predict(self, features: tuple[int, ...]) -> int:
        if len(features) != len(self.weights[0]):
            raise GenericMLProjectionError(
                "Generic-ML feature width differs from the frozen model"
            )
        scores = tuple(
            sum(weight * value for weight, value in zip(row, features, strict=True))
            + offset
            for row, offset in zip(self.weights, self.bias, strict=True)
        )
        # Tuple.index makes tied scores deterministically select the first class,
        # whose order is itself closed and strictly increasing.
        return self.class_labels[scores.index(max(scores))]


@dataclass(frozen=True, slots=True)
class GenericMLSeedPairedProjection:
    seed: int
    candidate_condition_id: str
    baseline_condition_id: str
    candidate_model_artifact_sha256: str
    candidate_model_record_hash: str
    baseline_model_artifact_sha256: str
    baseline_model_record_hash: str
    paired_predictions_artifact_sha256: str
    paired_predictions_record_hash: str
    robustness_artifact_sha256: str
    robustness_record_hash: str
    paired_unit_ids: tuple[str, ...]
    paired_unit_hashes: tuple[str, ...]
    reference_labels: tuple[int, ...]
    candidate_values: tuple[float, ...]
    baseline_values: tuple[float, ...]
    candidate_mean: float
    baseline_mean: float
    candidate_parameter_count: int
    baseline_parameter_count: int


@dataclass(frozen=True, slots=True)
class GenericMLProjectionFacts:
    run_id: str
    execution_run_id: str
    object_id: str
    task_id: str
    comparison_scope: str
    plan_artifact_sha256: str
    plan_record_hash: str
    raw_source_artifact_sha256: str
    raw_source_record_hash: str
    evaluation_contract_artifact_sha256: str
    evaluation_contract_record_hash: str
    dataset_authority_artifact_sha256: str
    dataset_authority_record_hash: str
    dataset_raw_artifact_sha256: str
    dataset_raw_record_hash: str
    split_authority_artifact_sha256s: tuple[str, ...]
    split_authority_record_hashes: tuple[str, ...]
    frozen_run_spec_artifact_sha256: str
    frozen_run_spec_record_hash: str
    frozen_model_configuration_artifact_sha256: str
    frozen_model_configuration_record_hash: str
    scientific_execution_authority_artifact_sha256: str
    scientific_execution_authority_record_hash: str
    scientific_execution_activity_artifact_sha256: str
    scientific_execution_activity_record_hash: str
    canonical_run_artifact_sha256: str
    canonical_run_record_hash: str
    canonical_run_content_hash: str
    output_manifest_artifact_sha256: str
    output_manifest_record_hash: str
    evaluator_artifact_sha256: str
    evaluator_record_hash: str
    environment_artifact_sha256: str
    environment_record_hash: str
    seed_order: tuple[int, ...]
    paired_unit_ids: tuple[str, ...]
    paired_unit_hashes: tuple[str, ...]
    reference_labels: tuple[int, ...]
    seed_projections: tuple[GenericMLSeedPairedProjection, ...]
    domain_consumed_output_artifact_sha256s: tuple[str, ...]
    domain_consumed_output_record_hashes: tuple[str, ...]
    ablation_output_artifact_sha256s: tuple[str, ...]
    ablation_output_record_hashes: tuple[str, ...]
    semantic_source_records: tuple[ArtifactRecord, ...]
    evidence: object


@dataclass(frozen=True, slots=True)
class GenericMLPairedMetricProjectionAuthority:
    projection_artifact_sha256: str
    projection_record_hash: str
    run_id: str
    execution_run_id: str
    object_id: str
    task_id: str
    comparison_scope: str
    scientific_domain_evidence_source_artifact_sha256: str
    scientific_domain_evidence_source_record_hash: str
    plan_artifact_sha256: str
    plan_record_hash: str
    raw_source_artifact_sha256: str
    raw_source_record_hash: str
    evaluation_contract_artifact_sha256: str
    evaluation_contract_record_hash: str
    dataset_authority_artifact_sha256: str
    dataset_authority_record_hash: str
    dataset_raw_artifact_sha256: str
    dataset_raw_record_hash: str
    split_authority_artifact_sha256s: tuple[str, ...]
    split_authority_record_hashes: tuple[str, ...]
    frozen_run_spec_artifact_sha256: str
    frozen_run_spec_record_hash: str
    frozen_model_configuration_artifact_sha256: str
    frozen_model_configuration_record_hash: str
    scientific_execution_authority_artifact_sha256: str
    scientific_execution_authority_record_hash: str
    scientific_execution_activity_artifact_sha256: str
    scientific_execution_activity_record_hash: str
    canonical_run_artifact_sha256: str
    canonical_run_record_hash: str
    canonical_run_content_hash: str
    output_manifest_artifact_sha256: str
    output_manifest_record_hash: str
    evaluator_artifact_sha256: str
    evaluator_record_hash: str
    environment_artifact_sha256: str
    environment_record_hash: str
    seed_order: tuple[int, ...]
    paired_unit_ids: tuple[str, ...]
    paired_unit_hashes: tuple[str, ...]
    reference_labels: tuple[int, ...]
    seed_projections: tuple[GenericMLSeedPairedProjection, ...]
    paired_projection_artifact_sha256s: tuple[str, ...]
    paired_projection_record_hashes: tuple[str, ...]
    domain_consumed_output_artifact_sha256s: tuple[str, ...]
    domain_consumed_output_record_hashes: tuple[str, ...]
    ablation_output_artifact_sha256s: tuple[str, ...]
    ablation_output_record_hashes: tuple[str, ...]
    ledger_event_id: str
    ledger_event_hash: str
    ledger_event_index: int
    status: str = "PROJECTED"
    scientific_evidence_eligible: bool = True


def _exact_int(value: object, label: str) -> int:
    if (
        type(value) is not int
        or value < -MAX_GENERIC_ML_INTEGER_MAGNITUDE
        or value > MAX_GENERIC_ML_INTEGER_MAGNITUDE
    ):
        raise GenericMLProjectionError(f"{label} is not a bounded exact integer")
    return value


def _exact_identifier(value: object, label: str) -> str:
    from .models import validate_identifier

    if not isinstance(value, str):
        raise GenericMLProjectionError(f"{label} is not text")
    try:
        validate_identifier(value, label)
    except ValidationError as exc:
        raise GenericMLProjectionError(f"{label} is invalid") from exc
    return value


def _exact_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise GenericMLProjectionError(f"{label} is not an exact SHA-256")
    return value


def _json_object(raw: bytes, label: str) -> Mapping[str, object]:
    if not isinstance(raw, bytes):
        raise GenericMLProjectionError(f"{label} bytes are not immutable")
    try:
        value = safe_json_loads(raw)
    except Exception as exc:
        raise GenericMLProjectionError(f"{label} is not bounded JSON") from exc
    if not isinstance(value, Mapping):
        raise GenericMLProjectionError(f"{label} is not an object")
    return value


def parse_bounded_integer_classification_dataset(
    raw: bytes,
) -> tuple[GenericMLClassificationRow, ...]:
    """Parse the reviewed Dataset envelope and derive label truth from rows."""

    value = _json_object(raw, "Generic-ML Dataset")
    if set(value) != {"schema_version", "dataset_id", "name", "version", "license", "data"}:
        raise GenericMLProjectionError("Generic-ML Dataset envelope is not exact")
    if value["schema_version"] != "scientific-dataset-source/v1":
        raise GenericMLProjectionError("Generic-ML Dataset envelope is unsupported")
    data = value.get("data")
    if not isinstance(data, list) or not 0 < len(data) <= MAX_GENERIC_ML_UNITS:
        raise GenericMLProjectionError("Generic-ML Dataset row count is unsupported")
    rows: list[GenericMLClassificationRow] = []
    widths: set[int] = set()
    for index, item in enumerate(data):
        if not isinstance(item, Mapping) or set(item) != {
            "schema_version",
            "unit_id",
            "features",
            "label",
        }:
            raise GenericMLProjectionError("Generic-ML Dataset row schema is not exact")
        if item["schema_version"] != GENERIC_ML_DATASET_ROW_SCHEMA:
            raise GenericMLProjectionError("Generic-ML Dataset row format is unsupported")
        unit_id = _exact_identifier(item["unit_id"], f"Generic-ML row {index} unit ID")
        features = item["features"]
        if (
            not isinstance(features, list)
            or not 0 < len(features) <= MAX_GENERIC_ML_FEATURES
        ):
            raise GenericMLProjectionError("Generic-ML feature vector is unsupported")
        typed_features = tuple(
            _exact_int(entry, "Generic-ML feature") for entry in features
        )
        widths.add(len(typed_features))
        label_value = _exact_int(item["label"], "Generic-ML reference label")
        rows.append(
            GenericMLClassificationRow(
                unit_id=unit_id,
                unit_hash=sha256_bytes(canonical_json_bytes(item)),
                features=typed_features,
                label=label_value,
            )
        )
    if len({row.unit_id for row in rows}) != len(rows) or len(widths) != 1:
        raise GenericMLProjectionError(
            "Generic-ML Dataset IDs are duplicated or feature widths differ"
        )
    class_labels = {row.label for row in rows}
    if not 1 < len(class_labels) <= MAX_GENERIC_ML_CLASSES:
        raise GenericMLProjectionError("Generic-ML Dataset class closure is unsupported")
    return tuple(rows)


def parse_integer_linear_model(
    raw: bytes,
    *,
    execution_run_id: str,
    frozen_run_spec_artifact_sha256: str,
    frozen_run_spec_sha256: str,
    seed: int,
    role: str,
    condition_id: str,
    code_sha256: str,
    configuration_sha256: str,
    expected_class_labels: tuple[int, ...],
    feature_count: int,
) -> GenericMLLinearModel:
    value = _json_object(raw, "Generic-ML model")
    required = {
        "schema_version",
        "execution_run_id",
        "frozen_run_spec_artifact_sha256",
        "frozen_run_spec_sha256",
        "seed",
        "role",
        "condition_id",
        "code_sha256",
        "configuration_sha256",
        "algorithm",
        "class_labels",
        "weights",
        "bias",
    }
    if set(value) != required:
        raise GenericMLProjectionError("Generic-ML model envelope is not exact")
    labels = value["class_labels"]
    weights = value["weights"]
    bias = value["bias"]
    if (
        value["schema_version"] != GENERIC_ML_MODEL_SCHEMA
        or value["execution_run_id"] != execution_run_id
        or value["frozen_run_spec_artifact_sha256"]
        != frozen_run_spec_artifact_sha256
        or value["frozen_run_spec_sha256"] != frozen_run_spec_sha256
        or value["seed"] != seed
        or value["role"] != role
        or value["condition_id"] != condition_id
        or value["code_sha256"] != code_sha256
        or value["configuration_sha256"] != configuration_sha256
        or value["algorithm"] != "LINEAR_ARGMAX_INTEGER_V1"
        or not isinstance(labels, list)
        or not 1 < len(labels) <= MAX_GENERIC_ML_CLASSES
        or not isinstance(weights, list)
        or len(weights) != len(labels)
        or not isinstance(bias, list)
        or len(bias) != len(labels)
    ):
        raise GenericMLProjectionError("Generic-ML model identity is substituted")
    typed_labels = tuple(_exact_int(item, "Generic-ML model class") for item in labels)
    if (
        typed_labels != expected_class_labels
        or typed_labels != tuple(sorted(set(typed_labels)))
    ):
        raise GenericMLProjectionError("Generic-ML model class closure differs")
    typed_weights: list[tuple[int, ...]] = []
    for row in weights:
        if not isinstance(row, list) or len(row) != feature_count:
            raise GenericMLProjectionError("Generic-ML model weight shape differs")
        typed_weights.append(
            tuple(_exact_int(item, "Generic-ML model weight") for item in row)
        )
    typed_bias = tuple(_exact_int(item, "Generic-ML model bias") for item in bias)
    return GenericMLLinearModel(
        seed=seed,
        role=role,
        condition_id=condition_id,
        class_labels=typed_labels,
        weights=tuple(typed_weights),
        bias=typed_bias,
        parameter_count=len(typed_labels) * feature_count + len(typed_labels),
    )


def _parse_frozen_linear_model_definition(
    value: object,
    *,
    seed: int,
    role: str,
    condition_id: str,
    expected_class_labels: tuple[int, ...],
    feature_count: int,
) -> GenericMLLinearModel:
    required = {
        "schema_version",
        "role",
        "condition_id",
        "algorithm",
        "class_labels",
        "weights",
        "bias",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise GenericMLProjectionError(
            "Generic-ML frozen model definition is not exact"
        )
    labels = value["class_labels"]
    weights = value["weights"]
    bias = value["bias"]
    if (
        value["schema_version"] != GENERIC_ML_FROZEN_MODEL_DEFINITION_SCHEMA
        or value["role"] != role
        or value["condition_id"] != condition_id
        or value["algorithm"] != "LINEAR_ARGMAX_INTEGER_V1"
        or not isinstance(labels, list)
        or not isinstance(weights, list)
        or not isinstance(bias, list)
        or len(weights) != len(labels)
        or len(bias) != len(labels)
    ):
        raise GenericMLProjectionError(
            "Generic-ML frozen model definition identity is substituted"
        )
    typed_labels = tuple(
        _exact_int(item, "Generic-ML frozen model class") for item in labels
    )
    if (
        typed_labels != expected_class_labels
        or typed_labels != tuple(sorted(set(typed_labels)))
    ):
        raise GenericMLProjectionError(
            "Generic-ML frozen model class closure differs"
        )
    typed_weights: list[tuple[int, ...]] = []
    for row in weights:
        if not isinstance(row, list) or len(row) != feature_count:
            raise GenericMLProjectionError(
                "Generic-ML frozen model weight shape differs"
            )
        typed_weights.append(
            tuple(
                _exact_int(item, "Generic-ML frozen model weight") for item in row
            )
        )
    typed_bias = tuple(
        _exact_int(item, "Generic-ML frozen model bias") for item in bias
    )
    parameter_count = len(typed_labels) * feature_count + len(typed_labels)
    if parameter_count > MAX_GENERIC_ML_FROZEN_MODEL_PARAMETERS:
        raise GenericMLProjectionError(
            "Generic-ML frozen model exceeds the reviewed parameter bound"
        )
    return GenericMLLinearModel(
        seed=seed,
        role=role,
        condition_id=condition_id,
        class_labels=typed_labels,
        weights=tuple(typed_weights),
        bias=typed_bias,
        parameter_count=parameter_count,
    )


def parse_frozen_model_configuration(
    raw: bytes,
    *,
    contract_artifact_sha256: str,
    contract_sha256: str,
    dataset_id: str,
    dataset_split_id: str,
    evaluator_id: str,
    metric_id: str,
    metric_unit: str,
    metric_scope: str,
    executed_baseline_ids: tuple[str, ...],
    seed_order: tuple[int, ...],
    candidate_condition_id: str,
    baseline_condition_id: str,
    expected_class_labels: tuple[int, ...],
    feature_count: int,
) -> tuple[tuple[GenericMLLinearModel, GenericMLLinearModel], ...]:
    """Parse exact prospective model definitions from the frozen input.

    The execution emits runtime-bound model envelopes, but their scientific
    parameters and condition roles must already be fixed in these bytes.
    """

    value = _json_object(raw, "Generic-ML frozen model configuration")
    required = {
        "schema_version",
        "contract_artifact_sha256",
        "contract_sha256",
        "dataset_id",
        "dataset_split_id",
        "evaluator_id",
        "metric_id",
        "metric_unit",
        "metric_scope",
        "executed_baseline_ids",
        "comparison_scope",
        "seed_model_definitions",
    }
    definitions = value.get("seed_model_definitions")
    if (
        set(value) != required
        or value.get("schema_version")
        != GENERIC_ML_FROZEN_MODEL_CONFIGURATION_SCHEMA
        or value.get("contract_artifact_sha256") != contract_artifact_sha256
        or value.get("contract_sha256") != contract_sha256
        or value.get("dataset_id") != dataset_id
        or value.get("dataset_split_id") != dataset_split_id
        or value.get("evaluator_id") != evaluator_id
        or value.get("metric_id") != metric_id
        or value.get("metric_unit") != metric_unit
        or value.get("metric_scope") != metric_scope
        or value.get("executed_baseline_ids") != list(executed_baseline_ids)
        or value.get("comparison_scope") != GENERIC_ML_COMPARISON_SCOPE
        or executed_baseline_ids != (baseline_condition_id,)
        or not isinstance(definitions, list)
        or len(definitions) != len(seed_order)
        or len(definitions) > MAX_GENERIC_ML_SEEDS
    ):
        raise GenericMLProjectionError(
            "Generic-ML frozen model configuration identity is substituted"
        )
    result: list[tuple[GenericMLLinearModel, GenericMLLinearModel]] = []
    total_parameters = 0
    for expected_seed, entry in zip(seed_order, definitions, strict=True):
        if (
            not isinstance(entry, Mapping)
            or set(entry) != {"seed", "candidate_model", "baseline_model"}
            or entry["seed"] != expected_seed
        ):
            raise GenericMLProjectionError(
                "Generic-ML frozen model grid differs from the frozen seeds"
            )
        candidate_model = _parse_frozen_linear_model_definition(
            entry["candidate_model"],
            seed=expected_seed,
            role="CANDIDATE",
            condition_id=candidate_condition_id,
            expected_class_labels=expected_class_labels,
            feature_count=feature_count,
        )
        baseline_model = _parse_frozen_linear_model_definition(
            entry["baseline_model"],
            seed=expected_seed,
            role="BASELINE",
            condition_id=baseline_condition_id,
            expected_class_labels=expected_class_labels,
            feature_count=feature_count,
        )
        total_parameters += (
            candidate_model.parameter_count + baseline_model.parameter_count
        )
        if total_parameters > MAX_GENERIC_ML_FROZEN_MODEL_GRID_PARAMETERS:
            raise GenericMLProjectionError(
                "Generic-ML frozen model grid exceeds the reviewed parameter bound"
            )
        result.append((candidate_model, baseline_model))
    return tuple(result)


def derive_frozen_model_reference_work(
    raw_dataset: bytes,
    raw_configuration: bytes,
    *,
    member_unit_ids: tuple[str, ...],
    member_unit_hashes: tuple[str, ...],
    seed_order: tuple[int, ...],
    contract_artifact_sha256: str,
    contract_sha256: str,
    dataset_id: str,
    dataset_split_id: str,
    evaluator_id: str,
    metric_id: str,
    metric_unit: str,
    metric_scope: str,
    candidate_condition_id: str,
    baseline_condition_id: str,
) -> GenericMLReferenceWork:
    """Pure exact-grid derivation; callers must separately replay all owners.

    Classes come from the whole Dataset, while work counts only the complete
    selected confirmatory partition. No labels or predictions are executed.
    """

    if (
        type(member_unit_ids) is not tuple
        or type(member_unit_hashes) is not tuple
        or not 0 < len(member_unit_ids) <= MAX_GENERIC_ML_UNITS
        or len(member_unit_ids) != len(member_unit_hashes)
        or any(type(item) is not str for item in (*member_unit_ids, *member_unit_hashes))
        or len(set(member_unit_ids)) != len(member_unit_ids)
        or type(seed_order) is not tuple
        or not 0 < len(seed_order) <= MAX_GENERIC_ML_SEEDS
        or any(type(seed) is not int or seed < 0 for seed in seed_order)
        or len(set(seed_order)) != len(seed_order)
    ):
        raise GenericMLProjectionError("reference-work partition or seed grid is not exact")
    for unit_id, unit_hash in zip(member_unit_ids, member_unit_hashes, strict=True):
        _exact_identifier(unit_id, "reference-work unit ID")
        _exact_sha256(unit_hash, "reference-work unit hash")
    rows = parse_bounded_integer_classification_dataset(raw_dataset)
    if _json_object(raw_dataset, "reference-work Dataset").get("dataset_id") != dataset_id:
        raise GenericMLProjectionError("reference-work Dataset identity differs")
    by_id = {row.unit_id: row for row in rows}
    if any(unit_id not in by_id for unit_id in member_unit_ids) or tuple(
        by_id[unit_id].unit_hash for unit_id in member_unit_ids
    ) != member_unit_hashes:
        raise GenericMLProjectionError("reference-work partition differs from exact Dataset rows")
    configuration = _json_object(raw_configuration, "reference-work configuration")
    definitions = configuration.get("seed_model_definitions")
    if (
        not isinstance(definitions, list)
        or any(
            not isinstance(item, Mapping) or type(item.get("seed")) is not int
            for item in definitions
        )
    ):
        raise GenericMLProjectionError("reference-work model seeds are not native integers")
    class_labels = tuple(sorted({row.label for row in rows}))
    feature_count = len(rows[0].features)
    parse_frozen_model_configuration(
        raw_configuration,
        contract_artifact_sha256=contract_artifact_sha256,
        contract_sha256=contract_sha256,
        dataset_id=dataset_id,
        dataset_split_id=dataset_split_id,
        evaluator_id=evaluator_id,
        metric_id=metric_id,
        metric_unit=metric_unit,
        metric_scope=metric_scope,
        executed_baseline_ids=(baseline_condition_id,),
        seed_order=seed_order,
        candidate_condition_id=candidate_condition_id,
        baseline_condition_id=baseline_condition_id,
        expected_class_labels=class_labels,
        feature_count=feature_count,
    )
    return GenericMLReferenceWork(
        unit_count=len(member_unit_ids),
        seed_count=len(seed_order),
        class_count=len(class_labels),
        feature_count=feature_count,
    )


def derive_paired_correctness(
    raw: bytes,
    *,
    execution_run_id: str,
    frozen_run_spec_artifact_sha256: str,
    frozen_run_spec_sha256: str,
    seed: int,
    evaluator_artifact_sha256: str,
    confirmatory_split_authority_artifact_sha256: str,
    metric_policy: Mapping[str, object],
    candidate_model_artifact_sha256: str,
    baseline_model_artifact_sha256: str,
    candidate_model: GenericMLLinearModel,
    baseline_model: GenericMLLinearModel,
    rows: tuple[GenericMLClassificationRow, ...],
) -> tuple[tuple[float, ...], tuple[float, ...], float, float]:
    value = _json_object(raw, "Generic-ML paired predictions")
    required = {
        "schema_version",
        "execution_run_id",
        "frozen_run_spec_artifact_sha256",
        "frozen_run_spec_sha256",
        "seed",
        "evaluator_artifact_sha256",
        "confirmatory_split_authority_artifact_sha256",
        "metric_policy",
        "candidate_model_artifact_sha256",
        "baseline_model_artifact_sha256",
        "rows",
    }
    predictions = value.get("rows")
    if (
        set(value) != required
        or value.get("schema_version") != GENERIC_ML_PREDICTIONS_SCHEMA
        or value.get("execution_run_id") != execution_run_id
        or value.get("frozen_run_spec_artifact_sha256")
        != frozen_run_spec_artifact_sha256
        or value.get("frozen_run_spec_sha256") != frozen_run_spec_sha256
        or value.get("seed") != seed
        or value.get("evaluator_artifact_sha256") != evaluator_artifact_sha256
        or value.get("confirmatory_split_authority_artifact_sha256")
        != confirmatory_split_authority_artifact_sha256
        or value.get("metric_policy") != dict(metric_policy)
        or value.get("candidate_model_artifact_sha256")
        != candidate_model_artifact_sha256
        or value.get("baseline_model_artifact_sha256")
        != baseline_model_artifact_sha256
        or not isinstance(predictions, list)
        or len(predictions) != len(rows)
    ):
        raise GenericMLProjectionError("Generic-ML prediction identity is substituted")
    candidate_values: list[float] = []
    baseline_values: list[float] = []
    for expected, observed in zip(rows, predictions, strict=True):
        if not isinstance(observed, Mapping) or set(observed) != {
            "unit_id",
            "unit_hash",
            "candidate_prediction",
            "baseline_prediction",
        }:
            raise GenericMLProjectionError("Generic-ML prediction row is not exact")
        candidate_prediction = _exact_int(
            observed["candidate_prediction"], "Generic-ML candidate prediction"
        )
        baseline_prediction = _exact_int(
            observed["baseline_prediction"], "Generic-ML baseline prediction"
        )
        if (
            observed["unit_id"] != expected.unit_id
            or observed["unit_hash"] != expected.unit_hash
            or candidate_prediction != candidate_model.predict(expected.features)
            or baseline_prediction != baseline_model.predict(expected.features)
        ):
            raise GenericMLProjectionError(
                "Generic-ML prediction differs from Dataset/model replay"
            )
        candidate_values.append(float(candidate_prediction == expected.label))
        baseline_values.append(float(baseline_prediction == expected.label))
    return (
        tuple(candidate_values),
        tuple(baseline_values),
        fmean(candidate_values),
        fmean(baseline_values),
    )


def validate_duplicate_inference_robustness(
    raw: bytes,
    *,
    execution_run_id: str,
    frozen_run_spec_artifact_sha256: str,
    frozen_run_spec_sha256: str,
    seed: int,
    evaluator_artifact_sha256: str,
    confirmatory_split_authority_artifact_sha256: str,
    candidate_model_artifact_sha256: str,
    candidate_model: GenericMLLinearModel,
    rows: tuple[GenericMLClassificationRow, ...],
) -> None:
    value = _json_object(raw, "Generic-ML robustness output")
    required = {
        "schema_version",
        "execution_run_id",
        "frozen_run_spec_artifact_sha256",
        "frozen_run_spec_sha256",
        "seed",
        "robustness_test_id",
        "evaluator_artifact_sha256",
        "confirmatory_split_authority_artifact_sha256",
        "candidate_model_artifact_sha256",
        "rows",
    }
    observations = value.get("rows")
    if (
        set(value) != required
        or value.get("schema_version") != GENERIC_ML_ROBUSTNESS_SCHEMA
        or value.get("execution_run_id") != execution_run_id
        or value.get("frozen_run_spec_artifact_sha256")
        != frozen_run_spec_artifact_sha256
        or value.get("frozen_run_spec_sha256") != frozen_run_spec_sha256
        or value.get("seed") != seed
        or value.get("robustness_test_id") != GENERIC_ML_ROBUSTNESS_TEST_ID
        or value.get("evaluator_artifact_sha256") != evaluator_artifact_sha256
        or value.get("confirmatory_split_authority_artifact_sha256")
        != confirmatory_split_authority_artifact_sha256
        or value.get("candidate_model_artifact_sha256")
        != candidate_model_artifact_sha256
        or not isinstance(observations, list)
        or len(observations) != len(rows)
    ):
        raise GenericMLProjectionError("Generic-ML robustness identity is substituted")
    for expected, observed in zip(rows, observations, strict=True):
        if not isinstance(observed, Mapping) or set(observed) != {
            "unit_id",
            "unit_hash",
            "first_prediction",
            "second_prediction",
        }:
            raise GenericMLProjectionError("Generic-ML robustness row is not exact")
        first = _exact_int(observed["first_prediction"], "robustness prediction")
        second = _exact_int(observed["second_prediction"], "robustness prediction")
        replayed = candidate_model.predict(expected.features)
        if (
            observed["unit_id"] != expected.unit_id
            or observed["unit_hash"] != expected.unit_hash
            or first != replayed
            or second != replayed
        ):
            raise GenericMLProjectionError(
                "Generic-ML robustness repetitions differ from model replay"
            )


def validate_generic_ml_observation_shape(
    value: object,
    *,
    prospective_policy: Mapping[str, object],
    seed_order: tuple[int, ...],
) -> tuple[tuple[Mapping[str, object], ...], tuple[Mapping[str, object], ...]]:
    """Validate authenticated v2 routing facts without treating them as outcomes."""

    required = {
        "schema_version",
        "actual_domain_policy",
        "loaded_pretrained_resource_inventory",
        "seed_outputs",
        "robustness_outputs",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise GenericMLProjectionError("Generic-ML v2 observations are not exact")
    if (
        value["schema_version"] != GENERIC_ML_OBSERVATIONS_SCHEMA
        or value["actual_domain_policy"] != dict(prospective_policy)
        or value["loaded_pretrained_resource_inventory"]
        != {
            "schema_version": GENERIC_ML_PRETRAINED_INVENTORY_SCHEMA,
            "completeness": "EXHAUSTIVE",
            "artifact_sha256s": [],
        }
    ):
        raise GenericMLProjectionError(
            "Generic-ML policy or loaded-resource inventory is substituted"
        )
    seed_outputs = value["seed_outputs"]
    robustness_outputs = value["robustness_outputs"]
    seed_keys = {
        "seed",
        "candidate_model_artifact_sha256",
        "candidate_model_record_hash",
        "baseline_model_artifact_sha256",
        "baseline_model_record_hash",
        "paired_predictions_artifact_sha256",
        "paired_predictions_record_hash",
    }
    robustness_keys = {
        "seed",
        "robustness_test_id",
        "artifact_sha256",
        "artifact_record_hash",
    }
    if (
        not isinstance(seed_outputs, list)
        or not isinstance(robustness_outputs, list)
        or len(seed_outputs) != len(seed_order)
        or len(robustness_outputs) != len(seed_order)
        or any(not isinstance(item, Mapping) or set(item) != seed_keys for item in seed_outputs)
        or any(
            not isinstance(item, Mapping) or set(item) != robustness_keys
            for item in robustness_outputs
        )
        or tuple(item["seed"] for item in seed_outputs) != seed_order
        or tuple(item["seed"] for item in robustness_outputs) != seed_order
        or any(
            item["robustness_test_id"] != GENERIC_ML_ROBUSTNESS_TEST_ID
            for item in robustness_outputs
        )
    ):
        raise GenericMLProjectionError(
            "Generic-ML observations do not cover the exact frozen seed grid"
        )
    for item in seed_outputs:
        for name in seed_keys - {"seed"}:
            _exact_sha256(item[name], f"Generic-ML {name}")
    for item in robustness_outputs:
        _exact_sha256(item["artifact_sha256"], "Generic-ML robustness output")
        _exact_sha256(item["artifact_record_hash"], "Generic-ML robustness record")
    return tuple(seed_outputs), tuple(robustness_outputs)


def partition_generic_ml_manifest_outputs(
    *,
    output_artifact_sha256s: tuple[str, ...],
    output_artifact_record_hashes: tuple[str, ...],
    output_logical_types: tuple[str, ...],
    expected_domain_output_artifact_sha256s: tuple[str, ...],
    required_ablation_count: int,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Return manifest indexes for the exhaustive domain/ablation partition."""

    if (
        len(output_artifact_sha256s) != len(output_artifact_record_hashes)
        or len(output_artifact_sha256s) != len(output_logical_types)
        or len(set(output_artifact_sha256s)) != len(output_artifact_sha256s)
        or type(required_ablation_count) is not int
        or required_ablation_count < 0
    ):
        raise GenericMLProjectionError("Generic-ML manifest closure is malformed")
    for digest in (*output_artifact_sha256s, *output_artifact_record_hashes):
        _exact_sha256(digest, "Generic-ML manifest identity")
    domain_indexes = tuple(
        index
        for index, logical_type in enumerate(output_logical_types)
        if logical_type != "experiment_output.ablation_output"
    )
    ablation_indexes = tuple(
        index
        for index, logical_type in enumerate(output_logical_types)
        if logical_type == "experiment_output.ablation_output"
    )
    if (
        len(ablation_indexes) != required_ablation_count
        or tuple(output_artifact_sha256s[index] for index in domain_indexes)
        != tuple(
            digest
            for digest in output_artifact_sha256s
            if digest in set(expected_domain_output_artifact_sha256s)
        )
        or {output_artifact_sha256s[index] for index in domain_indexes}
        != set(expected_domain_output_artifact_sha256s)
        or len(set(expected_domain_output_artifact_sha256s))
        != len(expected_domain_output_artifact_sha256s)
    ):
        raise GenericMLProjectionError(
            "Generic-ML manifest has an unconsumed, missing, or duplicated output"
        )
    return domain_indexes, ablation_indexes


def require_reference_accuracy_policy(
    value: object,
    *,
    metric_id: str,
    metric_unit: str,
    metric_direction: str,
    metric_aggregation: str,
) -> Mapping[str, object]:
    """Require the one exact v2 metric contract; names never select formulas."""

    expected = {
        "schema_version": GENERIC_ML_POLICY_SCHEMA,
        "metric_id": metric_id,
        "semantics": "EXACT_INTEGER_LABEL_MATCH",
        "aggregation": "MICRO_EXAMPLE_MEAN",
        "unit": "FRACTION",
        "direction": "HIGHER_IS_BETTER",
    }
    if (
        value != expected
        or metric_unit != "FRACTION"
        or metric_direction != "HIGHER_IS_BETTER"
        or metric_aggregation != "MICRO_EXAMPLE_MEAN"
    ):
        raise GenericMLProjectionError(
            "Generic-ML metric is not exact micro integer-label accuracy"
        )
    return expected


def _execution_output_record(
    registry: ArtifactRegistry,
    authority: object,
    digest: object,
    record_hash: object,
    *,
    logical_type: str,
    schema_version: str,
    label: str,
) -> ArtifactRecord:
    digest_value = _exact_sha256(digest, label)
    record_hash_value = _exact_sha256(record_hash, f"{label} record")
    indexes = tuple(
        index
        for index, value in enumerate(authority.output_artifact_sha256s)
        if value == digest_value
    )
    if len(indexes) != 1:
        raise GenericMLProjectionError(f"{label} is not one execution output")
    try:
        registry.verify(digest_value, raise_on_error=True)
        record = registry.get_metadata(digest_value)
    except (ArtifactError, ValidationError) as exc:
        raise GenericMLProjectionError(f"{label} cannot be reopened") from exc
    index = indexes[0]
    if (
        authority.output_artifact_record_hashes[index] != record_hash_value
        or record.record_hash != record_hash_value
        or record.logical_type != logical_type
        or record.schema_version != schema_version
        or record.mime_type != "application/json"
        or record.creator_role is not Role.EXPERIMENT_RUNNER
        or record.validation_result != "PASS"
        or record.frozen is not True
    ):
        raise GenericMLProjectionError(f"{label} metadata differs from execution")
    return record


def derive_generic_ml_projection_facts(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    candidate: object,
) -> GenericMLProjectionFacts:
    """Freshly derive the complete v2 source facts without publishing them."""

    # Local import avoids a module cycle: domains owns source authentication;
    # this module owns only the closed semantic projection.
    from . import domains as domain_owner
    from .research_state import (
        SCIENTIFIC_DATASET_ACQUISITION_ADAPTER_ID,
        SCIENTIFIC_DATASET_ACQUISITION_POLICY_ID,
        require_scientific_dataset_acquisition_plan,
    )

    plan = candidate.plan
    try:
        contract, dataset, splits, spec, records = (
            domain_owner._replay_scientific_domain_plan_sources(
                registry,
                ledger,
                run_id=plan.run_id,
                domain=plan.domain,
                object_id=plan.object_id,
                task_id=plan.task_id,
                source_format_id=plan.source_format_id,
                source_format_version=plan.source_format_version,
                evaluation_contract_artifact_sha256=(
                    plan.evaluation_contract_artifact_sha256
                ),
                dataset_authority_artifact_sha256=(
                    plan.dataset_authority_artifact_sha256
                ),
                split_authority_artifact_sha256s=(
                    plan.split_authority_artifact_sha256s
                ),
                frozen_run_spec_artifact_sha256=(
                    plan.frozen_run_spec_artifact_sha256
                ),
            )
        )
        acquisition = require_scientific_dataset_acquisition_plan(
            registry,
            ledger,
            run_id=plan.run_id,
            plan_artifact_hash=dataset.acquisition_plan_artifact_hash,
            expected_dataset_id=dataset.dataset_id,
            expected_version=dataset.version,
        )
    except Exception as exc:
        raise GenericMLProjectionError(
            "Generic-ML projection lost a prospective owner"
        ) from exc
    if (
        plan.source_format_version != GENERIC_ML_OBSERVATIONS_FORMAT_VERSION
        or acquisition.unit_id_field != "unit_id"
        or acquisition.adapter_id != SCIENTIFIC_DATASET_ACQUISITION_ADAPTER_ID
        or acquisition.policy_id != SCIENTIFIC_DATASET_ACQUISITION_POLICY_ID
        or len(spec.seeds) > MAX_GENERIC_ML_SEEDS
    ):
        raise GenericMLProjectionError(
            "Generic-ML v2 Dataset identity or seed bound is unsupported"
        )
    try:
        raw_record = registry.get_metadata(dataset.raw_data_artifact_hash)
        registry.verify(raw_record.sha256, raise_on_error=True)
        dataset_rows = parse_bounded_integer_classification_dataset(
            registry.get_bytes(raw_record.sha256)
        )
    except Exception as exc:
        if isinstance(exc, GenericMLProjectionError):
            raise
        raise GenericMLProjectionError("Generic-ML Dataset bytes cannot be replayed") from exc
    if (
        raw_record.record_hash != dataset.raw_data_record_hash
        or raw_record.sha256 != dataset.raw_data_artifact_hash
        or sha256_bytes(registry.get_bytes(raw_record.sha256)) != dataset.raw_data_sha256
    ):
        raise GenericMLProjectionError("Generic-ML Dataset raw identity differs")
    by_id = {row.unit_id: row for row in dataset_rows}
    for split in splits:
        try:
            split_rows = tuple(by_id[item] for item in split.member_unit_ids)
        except KeyError as exc:
            raise GenericMLProjectionError("Generic-ML split names an absent row") from exc
        if tuple(row.unit_hash for row in split_rows) != tuple(split.member_unit_hashes):
            raise GenericMLProjectionError("Generic-ML split hashes differ from raw rows")
    confirmatory = splits[3]
    confirmatory_rows = tuple(by_id[item] for item in confirmatory.member_unit_ids)
    class_labels = tuple(sorted({row.label for row in dataset_rows}))
    feature_count = len(dataset_rows[0].features)
    observations = candidate.raw_source_payload.get("domain_observations")
    prospective_policy = thaw_json(spec.metadata).get("scientific_domain_policy")
    if not isinstance(prospective_policy, Mapping):
        raise GenericMLProjectionError("Generic-ML prospective policy is absent")
    seed_outputs, robustness_outputs = validate_generic_ml_observation_shape(
        observations,
        prospective_policy=prospective_policy,
        seed_order=tuple(spec.seeds),
    )
    metric_policy = prospective_policy.get("metric_policy") if isinstance(prospective_policy, Mapping) else None
    require_reference_accuracy_policy(
        metric_policy,
        metric_id=contract.primary_metric.metric_id,
        metric_unit=contract.primary_metric.unit.value,
        metric_direction=contract.primary_metric.direction.value,
        metric_aggregation=contract.primary_metric.aggregation,
    )
    active_baselines = tuple(
        item
        for item in contract.baseline_registry.entries
        if item.status.value not in {"CONTEXT_ONLY", "INCOMPATIBLE"}
    )
    if len(active_baselines) != 1:
        raise GenericMLProjectionError("Generic-ML v2 requires exactly one comparator")
    baseline = active_baselines[0]
    if (
        prospective_policy.get("comparison_scope") != GENERIC_ML_COMPARISON_SCOPE
        or prospective_policy.get("preprocessing_fit_split_ids") != []
        or prospective_policy.get("checkpoint_selection_split_id") is not None
        or prospective_policy.get("early_stopping")
        != {"enabled": False, "monitor_split_id": None}
        or prospective_policy.get("augmentation")
        != {"mode": "NONE", "fit_split_ids": [], "application_split_ids": []}
        or contract.candidate_conditions.tuning_trials != 0
        or baseline.conditions.tuning_trials != 0
        or contract.candidate_conditions.hyperparameter_search.strip().casefold()
        != "none"
        or baseline.conditions.hyperparameter_search.strip().casefold() != "none"
        or contract.candidate_conditions.pretrained_resources.strip().casefold()
        != "none"
        or baseline.conditions.pretrained_resources.strip().casefold() != "none"
        or tuple(contract.robustness_tests) != (GENERIC_ML_ROBUSTNESS_TEST_ID,)
    ):
        raise GenericMLProjectionError(
            "Generic-ML v2 is not a frozen-model inference-only policy"
        )
    try:
        registry.verify(spec.configuration_sha256, raise_on_error=True)
        configuration_record = registry.get_metadata(spec.configuration_sha256)
        frozen_models = parse_frozen_model_configuration(
            registry.get_bytes(configuration_record.sha256),
            contract_artifact_sha256=plan.evaluation_contract_artifact_sha256,
            contract_sha256=contract.sha256,
            dataset_id=contract.dataset.dataset_id,
            dataset_split_id=contract.dataset.confirmatory_split_id,
            evaluator_id=contract.candidate_conditions.evaluator,
            metric_id=contract.primary_metric.metric_id,
            metric_unit=contract.primary_metric.unit.value,
            metric_scope=contract.primary_metric.scope.value,
            executed_baseline_ids=(baseline.baseline_id,),
            seed_order=tuple(spec.seeds),
            candidate_condition_id=spec.experiment_id,
            baseline_condition_id=baseline.baseline_id,
            expected_class_labels=class_labels,
            feature_count=feature_count,
        )
    except Exception as exc:
        if isinstance(exc, GenericMLProjectionError):
            raise
        raise GenericMLProjectionError(
            "Generic-ML prospective model configuration cannot be replayed"
        ) from exc
    if (
        configuration_record.logical_type != "experiment_configuration"
        or configuration_record.schema_version != "1.0"
        or configuration_record.mime_type != "application/json"
        or configuration_record.creator_role is not Role.PROTOCOL_DESIGNER
        or configuration_record.validation_result != "PASS"
        or configuration_record.frozen is not True
    ):
        raise GenericMLProjectionError(
            "Generic-ML prospective model configuration is not source-owned"
        )
    from .experiments import (
        ScientificDatasetAccessPurpose,
        ScientificExecutionActivityKind,
        require_scientific_execution_activity,
        resolve_scientific_reference_work_binding,
    )

    authority = candidate.scientific_execution_authority
    if (
        authority.execution_activity_artifact_sha256 is None
        or authority.execution_activity_record_hash is None
    ):
        raise GenericMLProjectionError(
            "Generic-ML v2 requires authenticated complete execution activity"
        )
    try:
        activity = require_scientific_execution_activity(
            registry,
            activity_artifact_sha256=authority.execution_activity_artifact_sha256,
            expected_ledger_run_id=plan.run_id,
            expected_execution_run_id=plan.execution_run_id,
            expected_preparation_artifact_sha256=authority.preparation_artifact_sha256,
            expected_frozen_run_spec_artifact_sha256=(
                plan.frozen_run_spec_artifact_sha256
            ),
            expected_output_manifest_artifact_sha256=(
                authority.output_manifest_artifact_sha256
            ),
        )
        activity_record = registry.get_metadata(
            authority.execution_activity_artifact_sha256
        )
    except Exception as exc:
        raise GenericMLProjectionError(
            "Generic-ML complete execution activity failed replay"
        ) from exc
    if activity_record.record_hash != authority.execution_activity_record_hash:
        raise GenericMLProjectionError("Generic-ML execution activity is substituted")
    no_recorded_selection_or_protected_label_access = not any(
        row.kind
        in {
            ScientificExecutionActivityKind.SELECTION_TRIAL,
            ScientificExecutionActivityKind.ADAPTIVE_BRANCH,
            ScientificExecutionActivityKind.EVALUATOR_QUERY,
        }
        or row.dataset_access_purpose
        is ScientificDatasetAccessPurpose.CONFIRMATORY_LABELS
        for row in activity.activity_rows
    )
    # Keep this narrow recorded-activity fact distinct from the complete
    # per-seed procedure check below. Neither proves the absence of training.
    procedure_activity_eligible = no_recorded_selection_or_protected_label_access
    evaluator_record = registry.get_metadata(spec.evaluator_sha256)
    environment_record = registry.get_metadata(
        candidate.scientific_execution_authority.environment_artifact_sha256
    )
    if (
        evaluator_record.validation_result != "PASS"
        or evaluator_record.frozen is not True
        or evaluator_record.creator_role is Role.HUMAN_RELEASE
        or environment_record.record_hash != authority.environment_record_hash
        or environment_record.validation_result != "PASS"
        or environment_record.frozen is not True
        or environment_record.creator_role is not Role.EXPERIMENT_RUNNER
    ):
        raise GenericMLProjectionError("Generic-ML evaluator/environment is ineligible")

    projections: list[GenericMLSeedPairedProjection] = []
    domain_records: list[ArtifactRecord] = []
    model_counts: list[tuple[int, int]] = []
    for seed, seed_value, robust_value, frozen_model_pair in zip(
        spec.seeds, seed_outputs, robustness_outputs, frozen_models, strict=True
    ):
        if (
            not isinstance(seed_value, Mapping)
            or set(seed_value)
            != {
                "seed",
                "candidate_model_artifact_sha256",
                "candidate_model_record_hash",
                "baseline_model_artifact_sha256",
                "baseline_model_record_hash",
                "paired_predictions_artifact_sha256",
                "paired_predictions_record_hash",
            }
            or not isinstance(robust_value, Mapping)
            or set(robust_value)
            != {
                "seed",
                "robustness_test_id",
                "artifact_sha256",
                "artifact_record_hash",
            }
            or seed_value["seed"] != seed
            or robust_value["seed"] != seed
            or robust_value["robustness_test_id"] != GENERIC_ML_ROBUSTNESS_TEST_ID
        ):
            raise GenericMLProjectionError("Generic-ML per-seed source map is not exact")
        candidate_record = _execution_output_record(
            registry,
            authority,
            seed_value["candidate_model_artifact_sha256"],
            seed_value["candidate_model_record_hash"],
            logical_type="experiment_output.generic_ml_model",
            schema_version=GENERIC_ML_MODEL_ARTIFACT_SCHEMA,
            label="Generic-ML candidate model",
        )
        baseline_record = _execution_output_record(
            registry,
            authority,
            seed_value["baseline_model_artifact_sha256"],
            seed_value["baseline_model_record_hash"],
            logical_type="experiment_output.generic_ml_model",
            schema_version=GENERIC_ML_MODEL_ARTIFACT_SCHEMA,
            label="Generic-ML baseline model",
        )
        prediction_record = _execution_output_record(
            registry,
            authority,
            seed_value["paired_predictions_artifact_sha256"],
            seed_value["paired_predictions_record_hash"],
            logical_type="experiment_output.generic_ml_paired_predictions",
            schema_version=GENERIC_ML_PREDICTIONS_ARTIFACT_SCHEMA,
            label="Generic-ML paired predictions",
        )
        robustness_record = _execution_output_record(
            registry,
            authority,
            robust_value["artifact_sha256"],
            robust_value["artifact_record_hash"],
            logical_type="experiment_output.generic_ml_robustness",
            schema_version=GENERIC_ML_ROBUSTNESS_ARTIFACT_SCHEMA,
            label="Generic-ML robustness output",
        )
        candidate_model = parse_integer_linear_model(
            registry.get_bytes(candidate_record.sha256),
            execution_run_id=plan.execution_run_id,
            frozen_run_spec_artifact_sha256=plan.frozen_run_spec_artifact_sha256,
            frozen_run_spec_sha256=spec.sha256,
            seed=seed,
            role="CANDIDATE",
            condition_id=spec.experiment_id,
            code_sha256=spec.code_sha256,
            configuration_sha256=spec.configuration_sha256,
            expected_class_labels=class_labels,
            feature_count=feature_count,
        )
        baseline_model = parse_integer_linear_model(
            registry.get_bytes(baseline_record.sha256),
            execution_run_id=plan.execution_run_id,
            frozen_run_spec_artifact_sha256=plan.frozen_run_spec_artifact_sha256,
            frozen_run_spec_sha256=spec.sha256,
            seed=seed,
            role="BASELINE",
            condition_id=baseline.baseline_id,
            code_sha256=spec.code_sha256,
            configuration_sha256=spec.configuration_sha256,
            expected_class_labels=class_labels,
            feature_count=feature_count,
        )
        if (candidate_model, baseline_model) != frozen_model_pair:
            raise GenericMLProjectionError(
                "Generic-ML execution model differs from its prospective definition"
            )
        candidate_values, baseline_values, candidate_mean, baseline_mean = (
            derive_paired_correctness(
                registry.get_bytes(prediction_record.sha256),
                execution_run_id=plan.execution_run_id,
                frozen_run_spec_artifact_sha256=plan.frozen_run_spec_artifact_sha256,
                frozen_run_spec_sha256=spec.sha256,
                seed=seed,
                evaluator_artifact_sha256=evaluator_record.sha256,
                confirmatory_split_authority_artifact_sha256=confirmatory.artifact_hash,
                metric_policy=metric_policy,
                candidate_model_artifact_sha256=candidate_record.sha256,
                baseline_model_artifact_sha256=baseline_record.sha256,
                candidate_model=candidate_model,
                baseline_model=baseline_model,
                rows=confirmatory_rows,
            )
        )
        validate_duplicate_inference_robustness(
            registry.get_bytes(robustness_record.sha256),
            execution_run_id=plan.execution_run_id,
            frozen_run_spec_artifact_sha256=plan.frozen_run_spec_artifact_sha256,
            frozen_run_spec_sha256=spec.sha256,
            seed=seed,
            evaluator_artifact_sha256=evaluator_record.sha256,
            confirmatory_split_authority_artifact_sha256=confirmatory.artifact_hash,
            candidate_model_artifact_sha256=candidate_record.sha256,
            candidate_model=candidate_model,
            rows=confirmatory_rows,
        )
        projections.append(
            GenericMLSeedPairedProjection(
                seed=seed,
                candidate_condition_id=spec.experiment_id,
                baseline_condition_id=baseline.baseline_id,
                candidate_model_artifact_sha256=candidate_record.sha256,
                candidate_model_record_hash=str(candidate_record.record_hash),
                baseline_model_artifact_sha256=baseline_record.sha256,
                baseline_model_record_hash=str(baseline_record.record_hash),
                paired_predictions_artifact_sha256=prediction_record.sha256,
                paired_predictions_record_hash=str(prediction_record.record_hash),
                robustness_artifact_sha256=robustness_record.sha256,
                robustness_record_hash=str(robustness_record.record_hash),
                paired_unit_ids=tuple(row.unit_id for row in confirmatory_rows),
                paired_unit_hashes=tuple(row.unit_hash for row in confirmatory_rows),
                reference_labels=tuple(row.label for row in confirmatory_rows),
                candidate_values=candidate_values,
                baseline_values=baseline_values,
                candidate_mean=candidate_mean,
                baseline_mean=baseline_mean,
                candidate_parameter_count=candidate_model.parameter_count,
                baseline_parameter_count=baseline_model.parameter_count,
            )
        )
        model_counts.append((candidate_model.parameter_count, baseline_model.parameter_count))
        domain_records.extend(
            (candidate_record, baseline_record, prediction_record, robustness_record)
        )
        expected_activity = (
            (
                ScientificExecutionActivityKind.MODEL_INVOCATION,
                spec.experiment_id,
                (),
                ((candidate_record.sha256, str(candidate_record.record_hash)),),
            ),
            (
                ScientificExecutionActivityKind.MODEL_INVOCATION,
                baseline.baseline_id,
                (),
                ((baseline_record.sha256, str(baseline_record.record_hash)),),
            ),
            (
                ScientificExecutionActivityKind.PREDICTION_GENERATION,
                spec.experiment_id,
                (
                    (candidate_record.sha256, str(candidate_record.record_hash)),
                    (baseline_record.sha256, str(baseline_record.record_hash)),
                ),
                ((prediction_record.sha256, str(prediction_record.record_hash)),),
            ),
            (
                ScientificExecutionActivityKind.OUTPUT_COMMIT,
                spec.experiment_id,
                ((prediction_record.sha256, str(prediction_record.record_hash)),),
                ((robustness_record.sha256, str(robustness_record.record_hash)),),
            ),
        )
        observed_rows = tuple(
            row
            for row in activity.activity_rows
            if row.seed == seed
            and row.kind
            in {
                ScientificExecutionActivityKind.MODEL_INVOCATION,
                ScientificExecutionActivityKind.PREDICTION_GENERATION,
                ScientificExecutionActivityKind.OUTPUT_COMMIT,
            }
            and row.ablation_id is None
        )
        observed_activity = tuple(
            (
                row.kind,
                row.condition_id,
                tuple(
                    (binding.artifact_sha256, binding.artifact_record_hash)
                    for binding in row.input_artifact_bindings
                ),
                tuple(
                    (binding.artifact_sha256, binding.artifact_record_hash)
                    for binding in row.output_artifact_bindings
                ),
            )
            for row in observed_rows
            if row.dataset_artifact_binding is None
            and row.split_artifact_binding is None
            and row.dataset_access_purpose is None
        )
        # Procedure integrity belongs to the execution-admissibility owner.
        # Preserve negative executions so it can issue an INADMISSIBLE verdict;
        # the domain receipt also receives a false procedure fact below.
        procedure_activity_eligible = (
            procedure_activity_eligible and observed_activity == expected_activity
        )
    if len(set(model_counts)) != 1:
        raise GenericMLProjectionError("Generic-ML model shape changes across seeds")
    by_hash: dict[str, ArtifactRecord] = {}
    for digest, record_hash in zip(
        authority.output_artifact_sha256s,
        authority.output_artifact_record_hashes,
        strict=True,
    ):
        registry.verify(digest, raise_on_error=True)
        output_record = registry.get_metadata(digest)
        if (
            output_record.record_hash != record_hash
            or output_record.creator_role is not Role.EXPERIMENT_RUNNER
            or output_record.validation_result != "PASS"
            or output_record.frozen is not True
        ):
            raise GenericMLProjectionError(
                "Generic-ML execution output closure is substituted"
            )
        by_hash[digest] = output_record
    expected_domain_hashes = {record.sha256 for record in domain_records}
    domain_indexes, ablation_indexes = partition_generic_ml_manifest_outputs(
        output_artifact_sha256s=tuple(authority.output_artifact_sha256s),
        output_artifact_record_hashes=tuple(authority.output_artifact_record_hashes),
        output_logical_types=tuple(
            by_hash[digest].logical_type
            for digest in authority.output_artifact_sha256s
        ),
        expected_domain_output_artifact_sha256s=tuple(expected_domain_hashes),
        required_ablation_count=len(spec.required_ablations),
    )
    actual_domain_records = tuple(
        by_hash[authority.output_artifact_sha256s[index]]
        for index in domain_indexes
    )
    ablation_records = tuple(
        by_hash[authority.output_artifact_sha256s[index]]
        for index in ablation_indexes
    )
    candidate_count, baseline_count = model_counts[0]
    policy = prospective_policy
    split_by_id = {split.split_id: split for split in splits}
    def domain_split_role(split: object) -> object:
        if split is splits[0]:
            return domain_owner.SplitRole.TRAIN
        if split in splits[1:3]:
            return domain_owner.SplitRole.VALIDATION
        return domain_owner.SplitRole.HOLDOUT

    try:
        preprocessing = tuple(
            dict.fromkeys(
                domain_split_role(split_by_id[item])
                for item in policy["preprocessing_fit_split_ids"]
            )
        )
        checkpoint_id = policy["checkpoint_selection_split_id"]
        checkpoint = (
            None
            if checkpoint_id is None
            else domain_split_role(split_by_id[checkpoint_id])
        )
        early = policy["early_stopping"]
        augmentation_value = policy["augmentation"]
        early_monitor_id = early["monitor_split_id"]
        early_monitor = (
            None
            if early_monitor_id is None
            else domain_split_role(split_by_id[early_monitor_id])
        )
        augmentation_fit = tuple(
            dict.fromkeys(
                domain_split_role(split_by_id[item])
                for item in augmentation_value["fit_split_ids"]
            )
        )
        augmentation_application = tuple(
            dict.fromkeys(
                domain_split_role(split_by_id[item])
                for item in augmentation_value["application_split_ids"]
            )
        )
    except Exception as exc:
        raise GenericMLProjectionError("Generic-ML policy split mapping is malformed") from exc
    evidence = domain_owner.GenericMLValidityEvidence(
        examples=tuple(
            domain_owner.GenericMLExample(
                example_id=unit_id,
                split=(
                    domain_split_role(split)
                ),
            )
            for split in splits
            for unit_id in split.member_unit_ids
        ),
        preprocessing_fit_splits=preprocessing,
        benchmark_version=dataset.version,
        pretrained_contamination_checked=True,
        seed_policy_frozen=procedure_activity_eligible,
        checkpoint_selection_split=checkpoint,
        metric_implementation_verified=True,
        hyperparameter_budget_equivalent=(
            contract.candidate_conditions.tuning_trials == 0
            and baseline.conditions.tuning_trials == 0
            and procedure_activity_eligible
        ),
        # The current execution authority provides one run-wide environment and
        # elapsed interval, not actual per-condition resource accounting.
        # Equal prospective budgets or operation counts cannot prove equality.
        compute_budget_equivalent=None,
        robustness_evaluated=True,
        generalization_claimed=False,
        external_validation_performed=None,
        early_stopping_policy=domain_owner.EarlyStoppingPolicyEvidence(
            enabled=early["enabled"],
            monitor_split=early_monitor,
            policy_artifact_sha256=plan.frozen_run_spec_artifact_sha256,
            timing=domain_owner.MLPolicyTiming.FROZEN_BEFORE_RESULTS,
        ),
        augmentation_policy=domain_owner.AugmentationPolicyEvidence(
            mode=domain_owner.AugmentationMode(augmentation_value["mode"]),
            fit_splits=augmentation_fit,
            application_splits=augmentation_application,
            policy_artifact_sha256=plan.frozen_run_spec_artifact_sha256,
            timing=domain_owner.MLPolicyTiming.FROZEN_BEFORE_RESULTS,
        ),
        model_resource_comparison=domain_owner.ModelResourceComparisonEvidence(
            candidate_parameter_count=candidate_count,
            baseline_parameter_count=baseline_count,
            candidate_resource_profile_sha256=environment_record.sha256,
            baseline_resource_profile_sha256=environment_record.sha256,
            parameter_count_disposition=(
                domain_owner.ComparisonDisposition.COMPARABLE
                if candidate_count == baseline_count
                else domain_owner.ComparisonDisposition.UNFAIR
            ),
            resource_disposition=domain_owner.ComparisonDisposition.UNAVAILABLE,
            comparison_artifact_sha256=candidate.raw_source_record.sha256,
        ),
        pretrained_resource_policy=domain_owner.PretrainedResourcePolicyEvidence(
            resources=(),
            inventory_artifact_sha256=candidate.raw_source_record.sha256,
            contamination_status=(
                domain_owner.PretrainedContaminationStatus.NOT_APPLICABLE
            ),
            contamination_assessment_artifact_sha256=None,
        ),
    )
    semantic: list[ArtifactRecord] = [
        raw_record,
        records[5],
        configuration_record,
        evaluator_record,
        environment_record,
        activity_record,
        registry.get_metadata(authority.output_manifest_artifact_sha256),
        *actual_domain_records,
    ]
    reference_binding = resolve_scientific_reference_work_binding(
        registry, spec=spec,
        expected_contract_artifact_sha256=plan.evaluation_contract_artifact_sha256,
    )
    if reference_binding is not None:
        # Select the new adapter input only after all actual model, prediction,
        # activity and robustness owners above, and the complete prospective
        # policy owner, agree. A declaration or caller-selected DTO is not an
        # alternative source of scientific evidence.
        observed_work = GenericMLReferenceWork(
            unit_count=len(confirmatory_rows), seed_count=len(projections),
            class_count=len(class_labels), feature_count=feature_count,
        )
        if (
            reference_binding.run_id != plan.run_id
            or reference_binding.execution_run_id != plan.execution_run_id
            or reference_binding.frozen_run_spec_sha256 != spec.sha256
            or reference_binding.contract_record.sha256 != plan.evaluation_contract_artifact_sha256
            or reference_binding.contract_record.record_hash != plan.evaluation_contract_record_hash
            or reference_binding.dataset_authority != dataset
            or reference_binding.dataset_record.sha256 != plan.dataset_authority_artifact_sha256
            or reference_binding.dataset_record.record_hash != plan.dataset_authority_record_hash
            or reference_binding.raw_data_record != raw_record
            or reference_binding.confirmatory_split_authority != confirmatory
            or reference_binding.confirmatory_split_record.sha256 != plan.split_authority_artifact_sha256s[3]
            or reference_binding.confirmatory_split_record.record_hash != plan.split_authority_record_hashes[3]
            or reference_binding.statistical_use_authority.member_unit_ids != tuple(row.unit_id for row in confirmatory_rows)
            or reference_binding.statistical_use_authority.member_unit_hashes != tuple(row.unit_hash for row in confirmatory_rows)
            or tuple(record.sha256 for record in reference_binding.input_records)
            != (spec.code_sha256, spec.data_sha256, spec.configuration_sha256, spec.evaluator_sha256)
            or reference_binding.input_records[2:] != (configuration_record, evaluator_record)
            or reference_binding.reference_work != observed_work
            or candidate_count != observed_work.class_count * (observed_work.feature_count + 1)
            or baseline_count != candidate_count
        ):
            raise GenericMLProjectionError("fixed-model reference-work sources differ from the complete observed grid")
        evidence = domain_owner.GenericMLFixedModelValidityEvidence(
            legacy_evidence=evidence,
            reference_work_policy=reference_binding.policy,
            reference_work=observed_work,
            statistical_use_authority_artifact_sha256=reference_binding.statistical_use_record.sha256,
            statistical_use_authority_record_hash=str(reference_binding.statistical_use_record.record_hash),
            no_recorded_selection_or_protected_label_access=no_recorded_selection_or_protected_label_access,
            requested_timeout_seconds=reference_binding.timeout_seconds,
            contract_wall_cap_seconds=reference_binding.contract_wall_cap_seconds,
        )
        semantic.extend(reference_binding.source_records)
    # Preserve the historical closure order on absence. On the new path, no
    # duplicate digest may conceal a different immutable source record.
    if len({record.sha256: record.record_hash for record in semantic}) != len(
        {(record.sha256, record.record_hash) for record in semantic}
    ):
        raise GenericMLProjectionError("Generic-ML semantic closure contains conflicting source records")
    semantic_unique = tuple(dict.fromkeys(record.sha256 for record in semantic))
    semantic_by_hash = {record.sha256: record for record in semantic}
    return GenericMLProjectionFacts(
        run_id=plan.run_id,
        execution_run_id=plan.execution_run_id,
        object_id=plan.object_id,
        task_id=plan.task_id,
        comparison_scope=GENERIC_ML_COMPARISON_SCOPE,
        plan_artifact_sha256=plan.plan_artifact_sha256,
        plan_record_hash=plan.plan_record_hash,
        raw_source_artifact_sha256=candidate.raw_source_record.sha256,
        raw_source_record_hash=str(candidate.raw_source_record.record_hash),
        evaluation_contract_artifact_sha256=plan.evaluation_contract_artifact_sha256,
        evaluation_contract_record_hash=plan.evaluation_contract_record_hash,
        dataset_authority_artifact_sha256=plan.dataset_authority_artifact_sha256,
        dataset_authority_record_hash=plan.dataset_authority_record_hash,
        dataset_raw_artifact_sha256=raw_record.sha256,
        dataset_raw_record_hash=str(raw_record.record_hash),
        split_authority_artifact_sha256s=plan.split_authority_artifact_sha256s,
        split_authority_record_hashes=plan.split_authority_record_hashes,
        frozen_run_spec_artifact_sha256=plan.frozen_run_spec_artifact_sha256,
        frozen_run_spec_record_hash=plan.frozen_run_spec_record_hash,
        frozen_model_configuration_artifact_sha256=configuration_record.sha256,
        frozen_model_configuration_record_hash=str(configuration_record.record_hash),
        scientific_execution_authority_artifact_sha256=(
            candidate.scientific_execution_authority_record.sha256
        ),
        scientific_execution_authority_record_hash=str(
            candidate.scientific_execution_authority_record.record_hash
        ),
        scientific_execution_activity_artifact_sha256=activity_record.sha256,
        scientific_execution_activity_record_hash=str(activity_record.record_hash),
        canonical_run_artifact_sha256=candidate.canonical_run_record.sha256,
        canonical_run_record_hash=str(candidate.canonical_run_record.record_hash),
        canonical_run_content_hash=(
            candidate.canonical_run_binding.research_object.content_hash
        ),
        output_manifest_artifact_sha256=authority.output_manifest_artifact_sha256,
        output_manifest_record_hash=authority.output_manifest_record_hash,
        evaluator_artifact_sha256=evaluator_record.sha256,
        evaluator_record_hash=str(evaluator_record.record_hash),
        environment_artifact_sha256=environment_record.sha256,
        environment_record_hash=str(environment_record.record_hash),
        seed_order=tuple(spec.seeds),
        paired_unit_ids=tuple(row.unit_id for row in confirmatory_rows),
        paired_unit_hashes=tuple(row.unit_hash for row in confirmatory_rows),
        reference_labels=tuple(row.label for row in confirmatory_rows),
        seed_projections=tuple(projections),
        domain_consumed_output_artifact_sha256s=tuple(
            record.sha256 for record in actual_domain_records
        ),
        domain_consumed_output_record_hashes=tuple(
            str(record.record_hash) for record in actual_domain_records
        ),
        ablation_output_artifact_sha256s=tuple(
            record.sha256 for record in ablation_records
        ),
        ablation_output_record_hashes=tuple(
            str(record.record_hash) for record in ablation_records
        ),
        semantic_source_records=tuple(semantic_by_hash[item] for item in semantic_unique),
        evidence=evidence,
    )


def _seed_projection_payload(
    facts: GenericMLProjectionFacts,
    source_artifact_sha256: str,
    projection: GenericMLSeedPairedProjection,
) -> Mapping[str, object]:
    return {
        "schema_version": GENERIC_ML_PROJECTION_SCHEMA,
        "run_id": facts.run_id,
        "execution_run_id": facts.execution_run_id,
        "object_id": facts.object_id,
        "task_id": facts.task_id,
        "comparison_scope": facts.comparison_scope,
        "scientific_domain_evidence_source_artifact_sha256": (
            source_artifact_sha256
        ),
        "frozen_model_configuration_artifact_sha256": (
            facts.frozen_model_configuration_artifact_sha256
        ),
        "frozen_model_configuration_record_hash": (
            facts.frozen_model_configuration_record_hash
        ),
        "seed": projection.seed,
        "candidate_condition_id": projection.candidate_condition_id,
        "baseline_condition_id": projection.baseline_condition_id,
        "candidate_model_artifact_sha256": (
            projection.candidate_model_artifact_sha256
        ),
        "candidate_model_record_hash": projection.candidate_model_record_hash,
        "baseline_model_artifact_sha256": (
            projection.baseline_model_artifact_sha256
        ),
        "baseline_model_record_hash": projection.baseline_model_record_hash,
        "paired_predictions_artifact_sha256": (
            projection.paired_predictions_artifact_sha256
        ),
        "paired_predictions_record_hash": (
            projection.paired_predictions_record_hash
        ),
        "robustness_artifact_sha256": projection.robustness_artifact_sha256,
        "robustness_record_hash": projection.robustness_record_hash,
        "paired_unit_ids": list(projection.paired_unit_ids),
        "paired_unit_hashes": list(projection.paired_unit_hashes),
        "reference_labels": list(projection.reference_labels),
        "candidate_values": list(projection.candidate_values),
        "baseline_values": list(projection.baseline_values),
        "candidate_mean": projection.candidate_mean,
        "baseline_mean": projection.baseline_mean,
        "candidate_parameter_count": projection.candidate_parameter_count,
        "baseline_parameter_count": projection.baseline_parameter_count,
        "metric_semantics": "EXACT_INTEGER_LABEL_MATCH",
        "aggregation": "MICRO_EXAMPLE_MEAN",
    }


def _authority_payload(
    facts: GenericMLProjectionFacts,
    *,
    source_record: ArtifactRecord,
    paired_records: tuple[ArtifactRecord, ...],
) -> Mapping[str, object]:
    return {
        "schema_version": GENERIC_ML_PROJECTION_AUTHORITY_SCHEMA,
        "run_id": facts.run_id,
        "execution_run_id": facts.execution_run_id,
        "object_id": facts.object_id,
        "task_id": facts.task_id,
        "comparison_scope": facts.comparison_scope,
        "scientific_domain_evidence_source_artifact_sha256": source_record.sha256,
        "scientific_domain_evidence_source_record_hash": str(
            source_record.record_hash
        ),
        "plan_artifact_sha256": facts.plan_artifact_sha256,
        "plan_record_hash": facts.plan_record_hash,
        "raw_source_artifact_sha256": facts.raw_source_artifact_sha256,
        "raw_source_record_hash": facts.raw_source_record_hash,
        "evaluation_contract_artifact_sha256": (
            facts.evaluation_contract_artifact_sha256
        ),
        "evaluation_contract_record_hash": facts.evaluation_contract_record_hash,
        "dataset_authority_artifact_sha256": (
            facts.dataset_authority_artifact_sha256
        ),
        "dataset_authority_record_hash": facts.dataset_authority_record_hash,
        "dataset_raw_artifact_sha256": facts.dataset_raw_artifact_sha256,
        "dataset_raw_record_hash": facts.dataset_raw_record_hash,
        "split_authority_artifact_sha256s": list(
            facts.split_authority_artifact_sha256s
        ),
        "split_authority_record_hashes": list(
            facts.split_authority_record_hashes
        ),
        "frozen_run_spec_artifact_sha256": (
            facts.frozen_run_spec_artifact_sha256
        ),
        "frozen_run_spec_record_hash": facts.frozen_run_spec_record_hash,
        "frozen_model_configuration_artifact_sha256": (
            facts.frozen_model_configuration_artifact_sha256
        ),
        "frozen_model_configuration_record_hash": (
            facts.frozen_model_configuration_record_hash
        ),
        "scientific_execution_authority_artifact_sha256": (
            facts.scientific_execution_authority_artifact_sha256
        ),
        "scientific_execution_authority_record_hash": (
            facts.scientific_execution_authority_record_hash
        ),
        "scientific_execution_activity_artifact_sha256": (
            facts.scientific_execution_activity_artifact_sha256
        ),
        "scientific_execution_activity_record_hash": (
            facts.scientific_execution_activity_record_hash
        ),
        "canonical_run_artifact_sha256": facts.canonical_run_artifact_sha256,
        "canonical_run_record_hash": facts.canonical_run_record_hash,
        "canonical_run_content_hash": facts.canonical_run_content_hash,
        "output_manifest_artifact_sha256": (
            facts.output_manifest_artifact_sha256
        ),
        "output_manifest_record_hash": facts.output_manifest_record_hash,
        "evaluator_artifact_sha256": facts.evaluator_artifact_sha256,
        "evaluator_record_hash": facts.evaluator_record_hash,
        "environment_artifact_sha256": facts.environment_artifact_sha256,
        "environment_record_hash": facts.environment_record_hash,
        "seed_order": list(facts.seed_order),
        "paired_unit_ids": list(facts.paired_unit_ids),
        "paired_unit_hashes": list(facts.paired_unit_hashes),
        "reference_labels": list(facts.reference_labels),
        "seed_projections": [
            _seed_projection_payload(facts, source_record.sha256, projection)
            for projection in facts.seed_projections
        ],
        "paired_projection_artifact_sha256s": [
            record.sha256 for record in paired_records
        ],
        "paired_projection_record_hashes": [
            str(record.record_hash) for record in paired_records
        ],
        "domain_consumed_output_artifact_sha256s": list(
            facts.domain_consumed_output_artifact_sha256s
        ),
        "domain_consumed_output_record_hashes": list(
            facts.domain_consumed_output_record_hashes
        ),
        "ablation_output_artifact_sha256s": list(
            facts.ablation_output_artifact_sha256s
        ),
        "ablation_output_record_hashes": list(
            facts.ablation_output_record_hashes
        ),
        "status": "PROJECTED",
        "scientific_evidence_eligible": True,
    }


def _projection_parent_hashes(
    facts: GenericMLProjectionFacts,
    *,
    source_record: ArtifactRecord,
    paired_records: tuple[ArtifactRecord, ...],
) -> tuple[str, ...]:
    ordered = (
        source_record.sha256,
        facts.plan_artifact_sha256,
        facts.raw_source_artifact_sha256,
        facts.evaluation_contract_artifact_sha256,
        facts.dataset_authority_artifact_sha256,
        facts.dataset_raw_artifact_sha256,
        *facts.split_authority_artifact_sha256s,
        facts.frozen_run_spec_artifact_sha256,
        facts.frozen_model_configuration_artifact_sha256,
        facts.scientific_execution_authority_artifact_sha256,
        facts.scientific_execution_activity_artifact_sha256,
        facts.canonical_run_artifact_sha256,
        facts.output_manifest_artifact_sha256,
        facts.evaluator_artifact_sha256,
        facts.environment_artifact_sha256,
        *facts.domain_consumed_output_artifact_sha256s,
        *(record.sha256 for record in paired_records),
    )
    return tuple(dict.fromkeys(ordered))


def _projection_plans(
    registry: ArtifactRegistry,
    facts: GenericMLProjectionFacts,
    *,
    source_record: ArtifactRecord,
    created_at: str,
) -> tuple[tuple[bytes, ArtifactRecord], ...]:
    from .domains import _scientific_domain_artifact_plan

    paired: list[tuple[bytes, ArtifactRecord]] = []
    for projection in facts.seed_projections:
        payload = _seed_projection_payload(facts, source_record.sha256, projection)
        parents = tuple(
            dict.fromkeys(
                (
                    source_record.sha256,
                    projection.candidate_model_artifact_sha256,
                    projection.baseline_model_artifact_sha256,
                    projection.paired_predictions_artifact_sha256,
                    projection.robustness_artifact_sha256,
                    facts.dataset_raw_artifact_sha256,
                    facts.split_authority_artifact_sha256s[3],
                    facts.frozen_model_configuration_artifact_sha256,
                    facts.evaluator_artifact_sha256,
                )
            )
        )
        paired.append(
            _scientific_domain_artifact_plan(
                registry,
                payload,
                logical_type=GENERIC_ML_PROJECTION_LOGICAL_TYPE,
                origin=(
                    "deterministic Generic-ML paired metric projection "
                    f"{facts.execution_run_id}:{projection.seed}"
                ),
                creator_role=Role.CLAIM_VERIFIER,
                creation_command=GENERIC_ML_PROJECTION_COMMAND,
                parent_artifacts=parents,
                schema_version=GENERIC_ML_PROJECTION_SCHEMA_VERSION,
                created_at=created_at,
            )
        )
    paired_records = tuple(record for _data, record in paired)
    authority_payload = _authority_payload(
        facts,
        source_record=source_record,
        paired_records=paired_records,
    )
    authority = _scientific_domain_artifact_plan(
        registry,
        authority_payload,
        logical_type=GENERIC_ML_PROJECTION_AUTHORITY_LOGICAL_TYPE,
        origin=f"deterministic Generic-ML projection authority {facts.execution_run_id}",
        creator_role=Role.CLAIM_VERIFIER,
        creation_command=GENERIC_ML_PROJECTION_COMMAND,
        parent_artifacts=_projection_parent_hashes(
            facts,
            source_record=source_record,
            paired_records=paired_records,
        ),
        schema_version=GENERIC_ML_PROJECTION_SCHEMA_VERSION,
        created_at=created_at,
    )
    return (*paired, authority)


def _projection_slot_records(
    registry: ArtifactRegistry,
    records: tuple[ArtifactRecord, ...],
    *,
    source_artifact_sha256: str,
) -> tuple[ArtifactRecord, ...]:
    result: list[ArtifactRecord] = []
    for record in records:
        if record.logical_type not in {
            GENERIC_ML_PROJECTION_LOGICAL_TYPE,
            GENERIC_ML_PROJECTION_AUTHORITY_LOGICAL_TYPE,
        }:
            continue
        try:
            value = safe_json_loads(registry.get_bytes(record.sha256))
        except Exception as exc:
            raise GenericMLProjectionError(
                "Generic-ML projection slot is unreadable"
            ) from exc
        if (
            isinstance(value, Mapping)
            and value.get("scientific_domain_evidence_source_artifact_sha256")
            == source_artifact_sha256
        ):
            result.append(record)
    return tuple(result)


def _projection_event_id(authority_artifact_sha256: str) -> str:
    _exact_sha256(authority_artifact_sha256, "Generic-ML projection authority")
    return f"evt-generic-ml-projection-{authority_artifact_sha256[:32]}"


def _projection_event_metadata(
    *,
    source_record: ArtifactRecord,
    paired_records: tuple[ArtifactRecord, ...],
    authority_record: ArtifactRecord,
) -> Mapping[str, object]:
    return {
        "generic_ml_paired_metric_projection": {
            "schema_version": GENERIC_ML_PROJECTION_EVENT_SCHEMA,
            "kind": "GENERIC_ML_PAIRED_METRICS_PROJECTED",
            "scientific_domain_evidence_source_artifact_sha256": (
                source_record.sha256
            ),
            "scientific_domain_evidence_source_record_hash": str(
                source_record.record_hash
            ),
            "paired_projection_artifact_sha256s": [
                record.sha256 for record in paired_records
            ],
            "paired_projection_record_hashes": [
                str(record.record_hash) for record in paired_records
            ],
            "projection_authority_artifact_sha256": authority_record.sha256,
            "projection_authority_record_hash": str(authority_record.record_hash),
        }
    }


def _source_candidate_and_facts(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    source_artifact_sha256: str,
) -> tuple[object, object, GenericMLProjectionFacts, ArtifactRecord]:
    from .domains import (
        DomainKind,
        SCIENTIFIC_DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION,
        SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID,
        _canonical_registry_object,
        _load_scientific_domain_source_candidate,
        require_scientific_domain_evidence_source,
    )

    source_record, source_value = _canonical_registry_object(
        registry,
        source_artifact_sha256,
        "Generic-ML scientific domain evidence source",
    )
    if (
        source_value.get("schema_version")
        != SCIENTIFIC_DOMAIN_EVIDENCE_SOURCE_SCHEMA_VERSION
        or source_value.get("domain") != DomainKind.GENERIC_ML.value
        or source_value.get("source_format_id")
        != SCIENTIFIC_DOMAIN_GENERIC_ML_OBSERVATIONS_FORMAT_ID
        or source_value.get("source_format_version")
        != GENERIC_ML_OBSERVATIONS_FORMAT_VERSION
    ):
        raise GenericMLProjectionError(
            "projection requires the exact Generic-ML v2 source profile"
        )
    source = require_scientific_domain_evidence_source(
        registry,
        ledger,
        source_artifact_sha256=source_artifact_sha256,
        expected_run_id=str(source_value.get("run_id")),
        expected_domain=DomainKind.GENERIC_ML,
        expected_object_id=str(source_value.get("object_id")),
        expected_task_id=str(source_value.get("task_id")),
    )
    candidate, _verifier = _load_scientific_domain_source_candidate(
        registry,
        ledger,
        plan_artifact_sha256=source.plan_artifact_sha256,
        raw_source_artifact_sha256=source.raw_source_artifact_sha256,
        scientific_execution_authority_artifact_sha256=(
            source.scientific_execution_authority_artifact_sha256
        ),
        canonical_run_artifact_sha256=source.canonical_run_artifact_sha256,
        expected_run_id=source.run_id,
        expected_domain=DomainKind.GENERIC_ML,
        expected_object_id=source.object_id,
        expected_task_id=source.task_id,
    )
    facts = derive_generic_ml_projection_facts(registry, ledger, candidate)
    if facts.evidence != source.evidence:
        raise GenericMLProjectionError(
            "projection facts differ from the authenticated scientific source"
        )
    return source, candidate, facts, source_record


def register_generic_ml_paired_metric_projection_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    scientific_domain_evidence_source_artifact_sha256: str,
) -> ArtifactRecord:
    """Publish projections from one source identity; accepts no outcome data."""

    from .domains import (
        _commit_scientific_domain_publication,
        _preflight_scientific_domain_publication,
        _require_scientific_domain_runtime,
        _require_scientific_domain_causal_time,
    )

    source, _candidate, facts, source_record = _source_candidate_and_facts(
        registry,
        ledger,
        source_artifact_sha256=(
            scientific_domain_evidence_source_artifact_sha256
        ),
    )
    registry_result, _ledger_result = _require_scientific_domain_runtime(
        registry,
        ledger,
        run_id=facts.run_id,
    )
    slot = _projection_slot_records(
        registry,
        registry_result.records,
        source_artifact_sha256=source_record.sha256,
    )
    timestamps = {record.created_at for record in slot}
    if len(timestamps) > 1:
        raise GenericMLProjectionError(
            "Generic-ML projection orphan timestamps disagree"
        )
    created_at = next(iter(timestamps), utc_now())
    _require_scientific_domain_causal_time(
        earlier=source_record.created_at,
        earlier_label="scientific domain source created time",
        later=created_at,
        later_label="Generic-ML projection created time",
        failure="Generic-ML projection time precedes its scientific source",
    )
    plans = _projection_plans(
        registry,
        facts,
        source_record=source_record,
        created_at=created_at,
    )
    expected_records = tuple(record for _data, record in plans)
    if slot and set(slot) != set(expected_records[: len(slot)]):
        if any(record not in expected_records for record in slot):
            raise GenericMLProjectionError(
                "Generic-ML projection slot binds other derivations"
            )
    paired_records = expected_records[:-1]
    authority_record = expected_records[-1]
    event_id = _projection_event_id(authority_record.sha256)
    registry_snapshot, ledger_snapshot, missing, event_to_append = (
        _preflight_scientific_domain_publication(
            registry,
            ledger,
            run_id=facts.run_id,
            plans=plans,
            event_id=event_id,
            event_timestamp=created_at,
            actor_role=Role.CLAIM_VERIFIER,
            event_artifact_hashes=tuple(record.sha256 for record in expected_records),
            reason=(
                "derived per-seed paired correctness from the exact Dataset, "
                "models, and label-free execution outputs"
            ),
            metadata=_projection_event_metadata(
                source_record=source_record,
                paired_records=paired_records,
                authority_record=authority_record,
            ),
            dataset_identifiers=(facts.dataset_authority_artifact_sha256,),
            random_seeds=facts.seed_order,
        )
    )
    committed = _commit_scientific_domain_publication(
        registry,
        ledger,
        plans=plans,
        registry_snapshot=registry_snapshot,
        ledger_snapshot=ledger_snapshot,
        missing=missing,
        event_to_append=event_to_append,
    )
    result = committed[-1]
    require_generic_ml_paired_metric_projection_authority(
        registry,
        ledger,
        projection_artifact_sha256=result.sha256,
        expected_ledger_run_id=source.run_id,
        expected_execution_run_id=source.execution_run_id,
        expected_domain_evidence_source_artifact_sha256=source.source_artifact_sha256,
        expected_contract_artifact_sha256=(
            source.evaluation_contract_artifact_sha256
        ),
        expected_output_manifest_artifact_sha256=(
            facts.output_manifest_artifact_sha256
        ),
    )
    return result


def require_generic_ml_paired_metric_projection_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    projection_artifact_sha256: str,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    expected_domain_evidence_source_artifact_sha256: str,
    expected_contract_artifact_sha256: str,
    expected_output_manifest_artifact_sha256: str,
) -> GenericMLPairedMetricProjectionAuthority:
    """Freshly replay source, Dataset, models, outputs, projection, and event."""

    from .domains import (
        _require_scientific_domain_causal_time,
        _require_scientific_domain_runtime,
    )

    source, _candidate, facts, source_record = _source_candidate_and_facts(
        registry,
        ledger,
        source_artifact_sha256=(
            expected_domain_evidence_source_artifact_sha256
        ),
    )
    if (
        facts.run_id != expected_ledger_run_id
        or facts.execution_run_id != expected_execution_run_id
        or facts.evaluation_contract_artifact_sha256
        != expected_contract_artifact_sha256
        or facts.output_manifest_artifact_sha256
        != expected_output_manifest_artifact_sha256
    ):
        raise GenericMLProjectionError("Generic-ML projection assertion is substituted")
    registry_result, ledger_result = _require_scientific_domain_runtime(
        registry,
        ledger,
        run_id=facts.run_id,
    )
    try:
        authority_record = registry.get_metadata(projection_artifact_sha256)
    except (ArtifactError, ValidationError) as exc:
        raise GenericMLProjectionError("Generic-ML projection authority is absent") from exc
    plans = _projection_plans(
        registry,
        facts,
        source_record=source_record,
        created_at=authority_record.created_at,
    )
    records = tuple(record for _data, record in plans)
    paired_records = records[:-1]
    expected_authority = records[-1]
    if authority_record != expected_authority or projection_artifact_sha256 != expected_authority.sha256:
        raise GenericMLProjectionError(
            "Generic-ML projection authority differs from fresh derivation"
        )
    _require_scientific_domain_causal_time(
        earlier=source_record.created_at,
        earlier_label="scientific domain source created time",
        later=authority_record.created_at,
        later_label="Generic-ML projection created time",
        failure="Generic-ML projection time precedes its scientific source",
    )
    for data, expected in plans:
        try:
            actual = registry.get_metadata(expected.sha256)
            actual_bytes = registry.get_bytes(expected.sha256)
        except (ArtifactError, ValidationError) as exc:
            raise GenericMLProjectionError("Generic-ML projection record is absent") from exc
        if actual != expected or actual_bytes != data:
            raise GenericMLProjectionError(
                "Generic-ML projection record differs from fresh derivation"
            )
    slot = _projection_slot_records(
        registry,
        registry_result.records,
        source_artifact_sha256=source_record.sha256,
    )
    if len(slot) != len(records) or set(slot) != set(records):
        raise GenericMLProjectionError("Generic-ML projection slot is incomplete or ambiguous")
    event_id = _projection_event_id(authority_record.sha256)
    matches = tuple(
        (index, event)
        for index, event in enumerate(ledger_result.events)
        if event.event_id == event_id
    )
    if len(matches) != 1 or matches[0][0] == 0 or matches[0][1].event_hash is None:
        raise GenericMLProjectionError("Generic-ML projection event is absent or ambiguous")
    event_index, event = matches[0]
    prior = ledger_result.events[event_index - 1]
    from .ledger import LedgerEvent

    expected_event = LedgerEvent.create(
        run_id=facts.run_id,
        actor_role=Role.CLAIM_VERIFIER,
        state_before=prior.requested_state_after,
        requested_state_after=prior.requested_state_after,
        artifact_hashes=tuple(record.sha256 for record in records),
        code_version=prior.code_version,
        configuration_hash=prior.configuration_hash,
        dataset_identifiers=(facts.dataset_authority_artifact_sha256,),
        random_seeds=facts.seed_order,
        reason=(
            "derived per-seed paired correctness from the exact Dataset, "
            "models, and label-free execution outputs"
        ),
        prior_event_hash=prior.event_hash,
        event_id=event_id,
        timestamp=authority_record.created_at,
        event_type="CHECKPOINT",
        metadata=_projection_event_metadata(
            source_record=source_record,
            paired_records=paired_records,
            authority_record=authority_record,
        ),
    )
    if (
        event != expected_event
        or event_index <= source.source_event_index
        or any(record.created_at != authority_record.created_at for record in records)
        or any(
            later.event_type == "CORRECTION"
            and later.supersedes_event_id == event.event_id
            for later in ledger_result.events[event_index + 1 :]
        )
    ):
        raise GenericMLProjectionError("Generic-ML projection event is stale or substituted")
    return GenericMLPairedMetricProjectionAuthority(
        projection_artifact_sha256=authority_record.sha256,
        projection_record_hash=str(authority_record.record_hash),
        run_id=facts.run_id,
        execution_run_id=facts.execution_run_id,
        object_id=facts.object_id,
        task_id=facts.task_id,
        comparison_scope=facts.comparison_scope,
        scientific_domain_evidence_source_artifact_sha256=source_record.sha256,
        scientific_domain_evidence_source_record_hash=str(source_record.record_hash),
        plan_artifact_sha256=facts.plan_artifact_sha256,
        plan_record_hash=facts.plan_record_hash,
        raw_source_artifact_sha256=facts.raw_source_artifact_sha256,
        raw_source_record_hash=facts.raw_source_record_hash,
        evaluation_contract_artifact_sha256=facts.evaluation_contract_artifact_sha256,
        evaluation_contract_record_hash=facts.evaluation_contract_record_hash,
        dataset_authority_artifact_sha256=facts.dataset_authority_artifact_sha256,
        dataset_authority_record_hash=facts.dataset_authority_record_hash,
        dataset_raw_artifact_sha256=facts.dataset_raw_artifact_sha256,
        dataset_raw_record_hash=facts.dataset_raw_record_hash,
        split_authority_artifact_sha256s=facts.split_authority_artifact_sha256s,
        split_authority_record_hashes=facts.split_authority_record_hashes,
        frozen_run_spec_artifact_sha256=facts.frozen_run_spec_artifact_sha256,
        frozen_run_spec_record_hash=facts.frozen_run_spec_record_hash,
        frozen_model_configuration_artifact_sha256=(
            facts.frozen_model_configuration_artifact_sha256
        ),
        frozen_model_configuration_record_hash=(
            facts.frozen_model_configuration_record_hash
        ),
        scientific_execution_authority_artifact_sha256=(
            facts.scientific_execution_authority_artifact_sha256
        ),
        scientific_execution_authority_record_hash=(
            facts.scientific_execution_authority_record_hash
        ),
        scientific_execution_activity_artifact_sha256=(
            facts.scientific_execution_activity_artifact_sha256
        ),
        scientific_execution_activity_record_hash=(
            facts.scientific_execution_activity_record_hash
        ),
        canonical_run_artifact_sha256=facts.canonical_run_artifact_sha256,
        canonical_run_record_hash=facts.canonical_run_record_hash,
        canonical_run_content_hash=facts.canonical_run_content_hash,
        output_manifest_artifact_sha256=facts.output_manifest_artifact_sha256,
        output_manifest_record_hash=facts.output_manifest_record_hash,
        evaluator_artifact_sha256=facts.evaluator_artifact_sha256,
        evaluator_record_hash=facts.evaluator_record_hash,
        environment_artifact_sha256=facts.environment_artifact_sha256,
        environment_record_hash=facts.environment_record_hash,
        seed_order=facts.seed_order,
        paired_unit_ids=facts.paired_unit_ids,
        paired_unit_hashes=facts.paired_unit_hashes,
        reference_labels=facts.reference_labels,
        seed_projections=facts.seed_projections,
        paired_projection_artifact_sha256s=tuple(
            record.sha256 for record in paired_records
        ),
        paired_projection_record_hashes=tuple(
            str(record.record_hash) for record in paired_records
        ),
        domain_consumed_output_artifact_sha256s=(
            facts.domain_consumed_output_artifact_sha256s
        ),
        domain_consumed_output_record_hashes=(
            facts.domain_consumed_output_record_hashes
        ),
        ablation_output_artifact_sha256s=facts.ablation_output_artifact_sha256s,
        ablation_output_record_hashes=facts.ablation_output_record_hashes,
        ledger_event_id=event.event_id,
        ledger_event_hash=str(event.event_hash),
        ledger_event_index=event_index,
    )


def require_current_generic_ml_paired_metric_projection_authority(
    registry: ArtifactRegistry,
    ledger: EventLedger,
    *,
    scientific_domain_evidence_source_artifact_sha256: str,
    expected_ledger_run_id: str,
    expected_execution_run_id: str,
    expected_contract_artifact_sha256: str,
    expected_output_manifest_artifact_sha256: str,
) -> GenericMLPairedMetricProjectionAuthority:
    """Resolve the sole complete projection authority for one source slot."""

    records = registry.verify_all(raise_on_error=True).records
    slot = _projection_slot_records(
        registry,
        records,
        source_artifact_sha256=(
            scientific_domain_evidence_source_artifact_sha256
        ),
    )
    authorities = tuple(
        record
        for record in slot
        if record.logical_type == GENERIC_ML_PROJECTION_AUTHORITY_LOGICAL_TYPE
    )
    if len(authorities) != 1:
        raise GenericMLProjectionError(
            "Generic-ML source lacks one complete projection authority"
        )
    return require_generic_ml_paired_metric_projection_authority(
        registry,
        ledger,
        projection_artifact_sha256=authorities[0].sha256,
        expected_ledger_run_id=expected_ledger_run_id,
        expected_execution_run_id=expected_execution_run_id,
        expected_domain_evidence_source_artifact_sha256=(
            scientific_domain_evidence_source_artifact_sha256
        ),
        expected_contract_artifact_sha256=expected_contract_artifact_sha256,
        expected_output_manifest_artifact_sha256=(
            expected_output_manifest_artifact_sha256
        ),
    )


__all__ = [
    "GENERIC_ML_ATTESTATION_SCHEMA",
    "GENERIC_ML_COMPARISON_SCOPE",
    "GENERIC_ML_FROZEN_MODEL_CONFIGURATION_SCHEMA",
    "GENERIC_ML_FROZEN_MODEL_DEFINITION_SCHEMA",
    "GENERIC_ML_MODEL_SCHEMA",
    "GENERIC_ML_MODEL_ARTIFACT_SCHEMA",
    "GENERIC_ML_OBSERVATIONS_FORMAT_VERSION",
    "GENERIC_ML_OBSERVATIONS_SCHEMA",
    "GENERIC_ML_POLICY_SCHEMA",
    "GENERIC_ML_PREDICTIONS_SCHEMA",
    "GENERIC_ML_PREDICTIONS_ARTIFACT_SCHEMA",
    "GENERIC_ML_PROJECTION_AUTHORITY_SCHEMA",
    "GENERIC_ML_PROJECTION_SCHEMA",
    "GENERIC_ML_REFERENCE_WORK_POLICY_SCHEMA",
    "GENERIC_ML_REFERENCE_WORK_PROFILE_ID",
    "GENERIC_ML_REFERENCE_WORK_SCHEMA",
    "GENERIC_ML_REFERENCE_WORK_SCOPE",
    "GENERIC_ML_REFERENCE_WORK_WALL_CAP_SCOPE",
    "GENERIC_ML_ROBUSTNESS_SCHEMA",
    "GENERIC_ML_ROBUSTNESS_ARTIFACT_SCHEMA",
    "GENERIC_ML_ROBUSTNESS_TEST_ID",
    "GENERIC_ML_VERIFIER_ID",
    "GenericMLClassificationRow",
    "GenericMLLinearModel",
    "GenericMLPairedMetricProjectionAuthority",
    "GenericMLProjectionError",
    "GenericMLProjectionFacts",
    "GenericMLReferenceWork",
    "GenericMLReferenceWorkPolicy",
    "GenericMLSeedPairedProjection",
    "derive_generic_ml_projection_facts",
    "derive_frozen_model_reference_work",
    "derive_paired_correctness",
    "parse_bounded_integer_classification_dataset",
    "parse_frozen_model_configuration",
    "parse_integer_linear_model",
    "parse_generic_ml_reference_work_policy",
    "partition_generic_ml_manifest_outputs",
    "validate_duplicate_inference_robustness",
    "validate_generic_ml_observation_shape",
    "register_generic_ml_paired_metric_projection_authority",
    "require_generic_ml_paired_metric_projection_authority",
    "require_current_generic_ml_paired_metric_projection_authority",
    "require_reference_accuracy_policy",
    "require_generic_ml_reference_work_wall_cap",
]
