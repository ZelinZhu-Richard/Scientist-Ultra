"""Pure declared feature-contribution intervention, not scientific authority.

The one closed operator zeros every class's candidate weight at the declared
input feature indices. It preserves biases, the remaining coefficients, class
order, first-maximum tie rule and baseline. A seed whose selected coefficients
are already zero remains in the grid; only a whole-grid coefficient no-op is
refused. Zero, beneficial and detrimental accuracy changes are all retained.

This describes an operational intervention on fixed models, NOT meaningful
component removal, mechanistic completeness, execution, independence,
prospectivity or R5/E2 adequacy. Expected identities and content-consistent row
hashes are caller-reproducible checks, not Dataset/contract/custody authority.
An eventual source owner must freeze and replay the full policy and source
grid, budget ALL required interventions jointly, and preflight output bytes,
parents and activity. There is no issuer, registry, ledger or production gate.

All effects below are exact descriptive micro-accuracy differences over the
fixed seed-by-row grid. There are no p-values, intervals, alpha allocations,
significance/equivalence decisions or scientific PASS values. The reference
product ceiling counts this component's THREE dense prediction grids, not
runtime, hardware cost or statistical adequacy. Existing source-model bounds
apply to the candidate+baseline grid; the derived third grid is not a new
frozen source model and has its own work accounted for in that ceiling.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .errors import ValidationError
from .generic_ml_projection import (
    GENERIC_ML_DATASET_ROW_SCHEMA,
    MAX_GENERIC_ML_CLASSES,
    MAX_GENERIC_ML_FEATURES,
    MAX_GENERIC_ML_FROZEN_MODEL_GRID_PARAMETERS,
    MAX_GENERIC_ML_FROZEN_MODEL_PARAMETERS,
    MAX_GENERIC_ML_INTEGER_MAGNITUDE,
    MAX_GENERIC_ML_SEEDS,
    GenericMLClassificationRow,
    GenericMLLinearModel,
)
from .models import validate_identifier, validate_sha256
from .security import canonical_json_bytes, sha256_bytes


GENERIC_ML_FEATURE_INTERVENTION_SCHEMA = "generic-ml-feature-intervention/v1"
GENERIC_ML_ABLATION_GRID_SCHEMA = "generic-ml-feature-intervention-grid/v1"
GENERIC_ML_FEATURE_INTERVENTION_OPERATOR = "ZERO_DECLARED_INPUT_FEATURE_WEIGHTS_V1"
GENERIC_ML_FEATURE_INTERVENTION_SCOPE = "DECLARED_FEATURE_CONTRIBUTION_INTERVENTION_ONLY"
MAX_GENERIC_ML_ABLATION_UNITS = 4096
MAX_GENERIC_ML_ABLATION_REFERENCE_PRODUCTS = 16_777_216


class GenericMLAblationError(ValidationError):
    """The pure intervention or its complete supplied grid is not exact."""


def _integer(value: object, label: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise GenericMLAblationError(f"{label} requires an exact integer in {low}..{high}")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str:
        raise GenericMLAblationError(f"{label} requires native identifier text")
    try:
        return validate_identifier(value, label)
    except ValidationError as exc:
        raise GenericMLAblationError(str(exc)) from exc


def _sha256(value: object, label: str) -> str:
    if type(value) is not str:
        raise GenericMLAblationError(f"{label} requires native SHA-256 text")
    try:
        return validate_sha256(value, label)
    except ValidationError as exc:
        raise GenericMLAblationError(str(exc)) from exc


def _tuple(value: object, label: str, low: int, high: int) -> tuple:
    if type(value) is not tuple or not low <= len(value) <= high:
        raise GenericMLAblationError(f"{label} requires a native tuple of size {low}..{high}")
    return value


def _seed_order(value: object) -> tuple[int, ...]:
    seeds = _tuple(value, "expected seed order", 1, MAX_GENERIC_ML_SEEDS)
    for seed in seeds:
        _integer(seed, "seed", 0, MAX_GENERIC_ML_INTEGER_MAGNITUDE)
    if len(set(seeds)) != len(seeds):
        raise GenericMLAblationError("expected seed order contains duplicates")
    return seeds


def _unit_identities(ids: object, hashes: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    ids = _tuple(ids, "expected unit IDs", 1, MAX_GENERIC_ML_ABLATION_UNITS)
    hashes = _tuple(hashes, "expected unit hashes", len(ids), len(ids))
    for value in ids:
        _identifier(value, "unit_id")
    for value in hashes:
        _sha256(value, "unit_hash")
    if len(set(ids)) != len(ids) or len(set(hashes)) != len(hashes):
        raise GenericMLAblationError("expected unit identities contain duplicates")
    return ids, hashes


def _model_shape(value: object) -> tuple[int, int]:
    """Revalidate constructor-free native model leaves before invoking predict."""

    if type(value) is not GenericMLLinearModel:
        raise GenericMLAblationError("model requires the exact native GenericMLLinearModel type")
    _integer(value.seed, "model seed", 0, MAX_GENERIC_ML_INTEGER_MAGNITUDE)
    _identifier(value.condition_id, "model condition_id")
    if type(value.role) is not str or value.role not in {"CANDIDATE", "BASELINE", "ABLATION"}:
        raise GenericMLAblationError("model role is not exact")
    labels = _tuple(value.class_labels, "model class labels", 2, MAX_GENERIC_ML_CLASSES)
    for label in labels:
        _integer(label, "model class label", -MAX_GENERIC_ML_INTEGER_MAGNITUDE,
                 MAX_GENERIC_ML_INTEGER_MAGNITUDE)
    if any(left >= right for left, right in zip(labels, labels[1:])):
        raise GenericMLAblationError("model class labels must be strictly increasing")
    weights = _tuple(value.weights, "model weights", len(labels), len(labels))
    first = _tuple(weights[0], "model weight row", 1, MAX_GENERIC_ML_FEATURES)
    classes, features = len(labels), len(first)
    parameters = classes * (features + 1)
    _integer(value.parameter_count, "model parameter_count", 1,
             MAX_GENERIC_ML_FROZEN_MODEL_PARAMETERS)
    if parameters > MAX_GENERIC_ML_FROZEN_MODEL_PARAMETERS or value.parameter_count != parameters:
        raise GenericMLAblationError("model parameter count or capacity differs")
    for row in weights:
        _tuple(row, "model weight row", features, features)
        for weight in row:
            _integer(weight, "model weight", -MAX_GENERIC_ML_INTEGER_MAGNITUDE,
                     MAX_GENERIC_ML_INTEGER_MAGNITUDE)
    bias = _tuple(value.bias, "model bias", classes, classes)
    for offset in bias:
        _integer(offset, "model bias", -MAX_GENERIC_ML_INTEGER_MAGNITUDE,
                 MAX_GENERIC_ML_INTEGER_MAGNITUDE)
    return classes, features


def _require_grid_capacity(units: int, seeds: int, classes: int, features: int) -> int:
    """Bound all three prediction grids before any prediction loop."""

    _integer(units, "unit count", 1, MAX_GENERIC_ML_ABLATION_UNITS)
    _integer(seeds, "seed count", 1, MAX_GENERIC_ML_SEEDS)
    _integer(classes, "class count", 2, MAX_GENERIC_ML_CLASSES)
    _integer(features, "feature count", 1, MAX_GENERIC_ML_FEATURES)
    parameters = classes * (features + 1)
    if parameters > MAX_GENERIC_ML_FROZEN_MODEL_PARAMETERS:
        raise GenericMLAblationError("model parameter capacity exceeded")
    if 2 * seeds * parameters > MAX_GENERIC_ML_FROZEN_MODEL_GRID_PARAMETERS:
        raise GenericMLAblationError("candidate+baseline source grid parameter capacity exceeded")
    products = 3 * units * seeds * classes * features
    if products > MAX_GENERIC_ML_ABLATION_REFERENCE_PRODUCTS:
        raise GenericMLAblationError("three-grid reference-product capacity exceeded")
    return products


@dataclass(frozen=True, slots=True)
class GenericMLFeatureIntervention:
    """An inert declaration; possession does not establish prospective approval."""

    ablation_id: str
    hypothesis_id: str
    component_id: str
    candidate_condition_id: str
    baseline_condition_id: str
    intervention_condition_id: str
    feature_indices: tuple[int, ...]
    schema_version: str = GENERIC_ML_FEATURE_INTERVENTION_SCHEMA
    operator: str = GENERIC_ML_FEATURE_INTERVENTION_OPERATOR
    scope: str = GENERIC_ML_FEATURE_INTERVENTION_SCOPE

    def __post_init__(self) -> None:
        if type(self) is not GenericMLFeatureIntervention:
            raise GenericMLAblationError("intervention requires its exact native DTO type")
        for name in ("ablation_id", "hypothesis_id", "component_id", "candidate_condition_id",
                     "baseline_condition_id", "intervention_condition_id"):
            _identifier(getattr(self, name), name)
        if len({self.candidate_condition_id, self.baseline_condition_id,
                self.intervention_condition_id}) != 3:
            raise GenericMLAblationError("candidate/baseline/intervention condition IDs must be distinct")
        for name, expected in (("schema_version", GENERIC_ML_FEATURE_INTERVENTION_SCHEMA),
                               ("operator", GENERIC_ML_FEATURE_INTERVENTION_OPERATOR),
                               ("scope", GENERIC_ML_FEATURE_INTERVENTION_SCOPE)):
            value = getattr(self, name)
            if type(value) is not str or value != expected:
                raise GenericMLAblationError(f"unsupported exact intervention {name}")
        indices = _tuple(self.feature_indices, "feature_indices", 1, MAX_GENERIC_ML_FEATURES)
        for index in indices:
            _integer(index, "feature index", 0, MAX_GENERIC_ML_FEATURES - 1)
        if any(left >= right for left, right in zip(indices, indices[1:])):
            raise GenericMLAblationError("feature_indices must be sorted and unique")

    def to_dict(self) -> dict[str, object]:
        GenericMLFeatureIntervention.__post_init__(self)
        return {
            "schema_version": self.schema_version,
            "operator": self.operator,
            "scope": self.scope,
            "ablation_id": self.ablation_id,
            "hypothesis_id": self.hypothesis_id,
            "component_id": self.component_id,
            "candidate_condition_id": self.candidate_condition_id,
            "baseline_condition_id": self.baseline_condition_id,
            "intervention_condition_id": self.intervention_condition_id,
            "feature_indices": list(self.feature_indices),
        }

    @classmethod
    def from_dict(cls, value: object) -> GenericMLFeatureIntervention:
        # Do not traverse arbitrary Mapping/list subclasses or hash custom keys.
        if cls is not GenericMLFeatureIntervention:
            raise GenericMLAblationError("intervention codec requires its exact native DTO type")
        if (type(value) is not dict or len(value) != 10
                or any(type(key) is not str for key in value)):
            raise GenericMLAblationError("intervention codec requires an exact native object")
        if set(value) != {"schema_version", "operator", "scope", "ablation_id", "hypothesis_id",
                          "component_id", "candidate_condition_id", "baseline_condition_id",
                          "intervention_condition_id", "feature_indices"}:
            raise GenericMLAblationError("intervention codec fields are not closed")
        indices = value["feature_indices"]
        if type(indices) is not list or not 1 <= len(indices) <= MAX_GENERIC_ML_FEATURES:
            raise GenericMLAblationError("intervention codec requires a bounded native feature list")
        fields = dict(value)
        fields["feature_indices"] = tuple(indices)
        return cls(**fields)


@dataclass(frozen=True, slots=True)
class GenericMLAblationSeedResult:
    """Descriptive predictions; this DTO does not attest a real execution."""

    seed: int
    ablated_model: GenericMLLinearModel
    changed_coefficient_count: int
    candidate_predictions: tuple[int, ...]
    baseline_predictions: tuple[int, ...]
    ablated_predictions: tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self) is not GenericMLAblationSeedResult:
            raise GenericMLAblationError("seed result requires its exact native DTO type")
        _integer(self.seed, "result seed", 0, MAX_GENERIC_ML_INTEGER_MAGNITUDE)
        classes, features = _model_shape(self.ablated_model)
        if self.ablated_model.seed != self.seed or self.ablated_model.role != "ABLATION":
            raise GenericMLAblationError("ablated model/result seed or role differs")
        _integer(self.changed_coefficient_count, "changed coefficient count", 0, classes * features)
        units = len(_tuple(self.candidate_predictions, "candidate predictions", 1,
                           MAX_GENERIC_ML_ABLATION_UNITS))
        class_set = frozenset(self.ablated_model.class_labels)
        for name in ("candidate_predictions", "baseline_predictions", "ablated_predictions"):
            predictions = _tuple(getattr(self, name), name, units, units)
            for value in predictions:
                _integer(value, "predicted label", -MAX_GENERIC_ML_INTEGER_MAGNITUDE,
                         MAX_GENERIC_ML_INTEGER_MAGNITUDE)
                if value not in class_set:
                    raise GenericMLAblationError("predicted label is outside the class closure")

    def to_dict(self) -> dict[str, object]:
        GenericMLAblationSeedResult.__post_init__(self)
        model = self.ablated_model
        return {
            "seed": self.seed,
            "changed_coefficient_count": self.changed_coefficient_count,
            "ablated_model": {
                "seed": model.seed,
                "role": model.role,
                "condition_id": model.condition_id,
                "class_labels": list(model.class_labels),
                "weights": [list(row) for row in model.weights],
                "bias": list(model.bias),
                "parameter_count": model.parameter_count,
            },
            "candidate_predictions": list(self.candidate_predictions),
            "baseline_predictions": list(self.baseline_predictions),
            "ablated_predictions": list(self.ablated_predictions),
        }


@dataclass(frozen=True, slots=True)
class GenericMLAblationUnitCounts:
    """Exact fixed-seed counts, without an independent-seed or population claim."""

    unit_id: str
    unit_hash: str
    seed_count: int
    candidate_correct_count: int
    baseline_correct_count: int
    ablated_correct_count: int

    def __post_init__(self) -> None:
        if type(self) is not GenericMLAblationUnitCounts:
            raise GenericMLAblationError("unit counts require their exact native DTO type")
        _identifier(self.unit_id, "unit_id")
        _sha256(self.unit_hash, "unit_hash")
        _integer(self.seed_count, "seed count", 1, MAX_GENERIC_ML_SEEDS)
        for name in ("candidate_correct_count", "baseline_correct_count", "ablated_correct_count"):
            _integer(getattr(self, name), name, 0, self.seed_count)

    @property
    def candidate_minus_ablated_numerator(self) -> int:
        return self.candidate_correct_count - self.ablated_correct_count

    @property
    def ablated_minus_baseline_numerator(self) -> int:
        return self.ablated_correct_count - self.baseline_correct_count

    @property
    def candidate_minus_baseline_numerator(self) -> int:
        return self.candidate_correct_count - self.baseline_correct_count

    @property
    def effect_denominator(self) -> int:
        return self.seed_count

    def to_dict(self) -> dict[str, object]:
        GenericMLAblationUnitCounts.__post_init__(self)
        return {
            "unit_id": self.unit_id,
            "unit_hash": self.unit_hash,
            "seed_count": self.seed_count,
            "candidate_correct_count": self.candidate_correct_count,
            "baseline_correct_count": self.baseline_correct_count,
            "ablated_correct_count": self.ablated_correct_count,
        }


@dataclass(frozen=True, slots=True)
class GenericMLAblationGrid:
    """Closed, internally consistent descriptive output, never source authority.

    Numerators use candidate minus ablated, ablated minus baseline, and
    candidate minus baseline respectively. Each denominator is N*S (S for
    the per-unit view), deliberately unreduced so the complete grid remains
    visible. A negative candidate-minus-ablated effect is valid. Direct DTO
    construction establishes only native shape and arithmetic consistency;
    use derive_generic_ml_ablation_grid to recompute from supplied sources.
    """

    intervention: GenericMLFeatureIntervention
    seed_results: tuple[GenericMLAblationSeedResult, ...]
    unit_counts: tuple[GenericMLAblationUnitCounts, ...]
    reference_labels: tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self) is not GenericMLAblationGrid:
            raise GenericMLAblationError("grid requires its exact native DTO type")
        if type(self.intervention) is not GenericMLFeatureIntervention:
            raise GenericMLAblationError("intervention requires its exact native DTO type")
        GenericMLFeatureIntervention.__post_init__(self.intervention)
        seeds = _tuple(self.seed_results, "seed results", 1, MAX_GENERIC_ML_SEEDS)
        units = _tuple(self.unit_counts, "unit counts", 1, MAX_GENERIC_ML_ABLATION_UNITS)
        for seed in seeds:
            if type(seed) is not GenericMLAblationSeedResult:
                raise GenericMLAblationError("seed result requires its exact native DTO type")
            GenericMLAblationSeedResult.__post_init__(seed)
        for unit in units:
            if type(unit) is not GenericMLAblationUnitCounts:
                raise GenericMLAblationError("unit counts require their exact native DTO type")
            GenericMLAblationUnitCounts.__post_init__(unit)
        _seed_order(self.seed_order)
        _unit_identities(self.unit_ids, self.unit_hashes)
        model = seeds[0].ablated_model
        classes, features = len(model.class_labels), len(model.weights[0])
        _require_grid_capacity(len(units), len(seeds), classes, features)
        if self.intervention.feature_indices[-1] >= features:
            raise GenericMLAblationError("declared feature index is outside the model shape")
        if not any(seed.changed_coefficient_count for seed in seeds):
            raise GenericMLAblationError("whole requested seed grid is a coefficient no-op")
        for seed in seeds:
            current = seed.ablated_model
            if (current.condition_id != self.intervention.intervention_condition_id
                    or current.class_labels != model.class_labels
                    or len(current.weights[0]) != features
                    or len(seed.candidate_predictions) != len(units)):
                raise GenericMLAblationError("result model identity, shape or complete grid differs")
            if any(row[index] != 0 for row in current.weights
                   for index in self.intervention.feature_indices):
                raise GenericMLAblationError("result retains a declared feature coefficient")
            if seed.changed_coefficient_count > classes * len(self.intervention.feature_indices):
                raise GenericMLAblationError("changed count exceeds the declared coefficient group")
        labels = _tuple(self.reference_labels, "reference labels", len(units), len(units))
        class_set = frozenset(model.class_labels)
        for label in labels:
            _integer(label, "reference label", -MAX_GENERIC_ML_INTEGER_MAGNITUDE,
                     MAX_GENERIC_ML_INTEGER_MAGNITUDE)
            if label not in class_set:
                raise GenericMLAblationError("reference label is outside the class closure")
        for index, unit in enumerate(units):
            expected = tuple(sum(getattr(seed, name)[index] == labels[index] for seed in seeds)
                             for name in ("candidate_predictions", "baseline_predictions",
                                          "ablated_predictions"))
            if (unit.seed_count != len(seeds) or expected != (
                    unit.candidate_correct_count, unit.baseline_correct_count,
                    unit.ablated_correct_count)):
                raise GenericMLAblationError("unit counts differ from the complete prediction grid")

    @property
    def seed_order(self) -> tuple[int, ...]:
        return tuple(seed.seed for seed in self.seed_results)

    @property
    def unit_ids(self) -> tuple[str, ...]:
        return tuple(unit.unit_id for unit in self.unit_counts)

    @property
    def unit_hashes(self) -> tuple[str, ...]:
        return tuple(unit.unit_hash for unit in self.unit_counts)

    @property
    def reference_product_count(self) -> int:
        model = self.seed_results[0].ablated_model
        return 3 * len(self.unit_counts) * len(self.seed_results) * len(model.class_labels) * len(model.weights[0])

    @property
    def candidate_minus_ablated_numerator(self) -> int:
        return sum(unit.candidate_minus_ablated_numerator for unit in self.unit_counts)

    @property
    def ablated_minus_baseline_numerator(self) -> int:
        return sum(unit.ablated_minus_baseline_numerator for unit in self.unit_counts)

    @property
    def candidate_minus_baseline_numerator(self) -> int:
        return sum(unit.candidate_minus_baseline_numerator for unit in self.unit_counts)

    @property
    def effect_denominator(self) -> int:
        return len(self.unit_counts) * len(self.seed_results)

    def to_dict(self) -> dict[str, object]:
        GenericMLAblationGrid.__post_init__(self)
        return {
            "schema_version": GENERIC_ML_ABLATION_GRID_SCHEMA,
            "scope": GENERIC_ML_FEATURE_INTERVENTION_SCOPE,
            "intervention": self.intervention.to_dict(),
            "seed_order": list(self.seed_order),
            "reference_labels": list(self.reference_labels),
            "seed_results": [seed.to_dict() for seed in self.seed_results],
            "unit_counts": [unit.to_dict() for unit in self.unit_counts],
            "reference_product_count": self.reference_product_count,
            "effect_denominator": self.effect_denominator,
            "candidate_minus_ablated_numerator": self.candidate_minus_ablated_numerator,
            "ablated_minus_baseline_numerator": self.ablated_minus_baseline_numerator,
            "candidate_minus_baseline_numerator": self.candidate_minus_baseline_numerator,
        }


def derive_generic_ml_ablation_grid(
    intervention: GenericMLFeatureIntervention,
    *,
    model_pairs: tuple[tuple[GenericMLLinearModel, GenericMLLinearModel], ...],
    rows: tuple[GenericMLClassificationRow, ...],
    expected_seed_order: tuple[int, ...],
    expected_unit_ids: tuple[str, ...],
    expected_unit_hashes: tuple[str, ...],
) -> GenericMLAblationGrid:
    """Recompute one complete declared intervention from native fixed inputs.

    Expected seed/unit order is independently supplied, never inferred from a
    selected observed subset. Its authority/prospectivity remains outside this
    pure API. Every candidate/baseline model has the same full class and feature
    shape; confirmatory rows need not contain every class in that full closure.
    Input DTOs have no validating constructor, so neither their nominal type
    nor their parameter_count/hash is taken on trust. All scalar/container
    leaves are checked before custom hooks could reach hashing or arithmetic.
    """

    if type(intervention) is not GenericMLFeatureIntervention:
        raise GenericMLAblationError("intervention requires its exact native DTO type")
    GenericMLFeatureIntervention.__post_init__(intervention)
    # Own the declaration used for computation: later caller-side mutation of
    # a nominally frozen DTO must not relabel an already derived result.
    intervention = replace(intervention)
    seeds = _seed_order(expected_seed_order)
    ids, hashes = _unit_identities(expected_unit_ids, expected_unit_hashes)
    pairs = _tuple(model_pairs, "model pairs", len(seeds), len(seeds))
    rows = _tuple(rows, "confirmatory rows", len(ids), len(ids))
    for pair in pairs:
        _tuple(pair, "candidate/baseline pair", 2, 2)
        for model in pair:
            _model_shape(model)
    first_model = pairs[0][0]
    classes, features = len(first_model.class_labels), len(first_model.weights[0])
    for seed, (candidate, baseline) in zip(seeds, pairs, strict=True):
        for model, role, condition in (
            (candidate, "CANDIDATE", intervention.candidate_condition_id),
            (baseline, "BASELINE", intervention.baseline_condition_id),
        ):
            if (model.seed != seed or model.role != role or model.condition_id != condition
                    or model.class_labels != first_model.class_labels
                    or len(model.weights[0]) != features):
                raise GenericMLAblationError("source model seed/order/role/condition/class/feature closure differs")
    _require_grid_capacity(len(rows), len(seeds), classes, features)
    if intervention.feature_indices[-1] >= features:
        raise GenericMLAblationError("declared feature index is outside the model shape")
    # Revalidate EVERY row leaf before hashing any row or predicting any label.
    for row in rows:
        if type(row) is not GenericMLClassificationRow:
            raise GenericMLAblationError("row requires the exact native GenericMLClassificationRow type")
        _identifier(row.unit_id, "row unit_id")
        _sha256(row.unit_hash, "row unit_hash")
        _integer(row.label, "row label", -MAX_GENERIC_ML_INTEGER_MAGNITUDE,
                 MAX_GENERIC_ML_INTEGER_MAGNITUDE)
        values = _tuple(row.features, "row features", features, features)
        for value in values:
            _integer(value, "row feature", -MAX_GENERIC_ML_INTEGER_MAGNITUDE,
                     MAX_GENERIC_ML_INTEGER_MAGNITUDE)
    class_set = frozenset(first_model.class_labels)
    for row, unit_id, unit_hash in zip(rows, ids, hashes, strict=True):
        if row.unit_id != unit_id or row.unit_hash != unit_hash:
            raise GenericMLAblationError("row identity or complete expected unit order differs")
        if row.label not in class_set:
            raise GenericMLAblationError("row label is outside the full model class closure")
        derived_hash = sha256_bytes(canonical_json_bytes({
            "schema_version": GENERIC_ML_DATASET_ROW_SCHEMA,
            "unit_id": row.unit_id,
            "features": list(row.features),
            "label": row.label,
        }))
        if row.unit_hash != derived_hash:
            raise GenericMLAblationError("row content differs from its supplied unit hash")
    indices = frozenset(intervention.feature_indices)
    changed_counts = tuple(sum(row[index] != 0 for row in candidate.weights for index in indices)
                           for candidate, _ in pairs)
    if not any(changed_counts):
        raise GenericMLAblationError("whole requested seed grid is a coefficient no-op")
    seed_results: list[GenericMLAblationSeedResult] = []
    counts = [[0, 0, 0] for _ in rows]
    for (candidate, baseline), changed in zip(pairs, changed_counts, strict=True):
        ablated = GenericMLLinearModel(
            seed=candidate.seed,
            role="ABLATION",
            condition_id=intervention.intervention_condition_id,
            class_labels=candidate.class_labels,
            weights=tuple(tuple(0 if index in indices else weight
                                for index, weight in enumerate(row)) for row in candidate.weights),
            bias=candidate.bias,
            parameter_count=candidate.parameter_count,
        )
        predictions = tuple(tuple(GenericMLLinearModel.predict(model, row.features) for row in rows)
                            for model in (candidate, baseline, ablated))
        for index, row in enumerate(rows):
            for condition in range(3):
                counts[index][condition] += predictions[condition][index] == row.label
        seed_results.append(GenericMLAblationSeedResult(
            seed=candidate.seed,
            ablated_model=ablated,
            changed_coefficient_count=changed,
            candidate_predictions=predictions[0],
            baseline_predictions=predictions[1],
            ablated_predictions=predictions[2],
        ))
    return GenericMLAblationGrid(
        intervention=intervention,
        seed_results=tuple(seed_results),
        unit_counts=tuple(GenericMLAblationUnitCounts(
            unit_id=row.unit_id, unit_hash=row.unit_hash, seed_count=len(seeds),
            candidate_correct_count=values[0], baseline_correct_count=values[1],
            ablated_correct_count=values[2],
        ) for row, values in zip(rows, counts, strict=True)),
        reference_labels=tuple(row.label for row in rows),
    )
