"""Dependency-free scientific design validation and small-sample analyses.

The module makes the independent unit, resampling unit, exchangeability
assumptions, effect estimate, uncertainty method, and multiplicity family
explicit.  It is intentionally conservative: an analysis fails closed when a
seed, fold, checkpoint, time point, or repeated measurement is presented as an
independent unit without an explicit scientific justification.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import itertools
import math
import random
from statistics import fmean, stdev
from typing import Any, Iterable, Sequence

from .errors import ValidationError


class StatisticalValidationError(ValidationError):
    """A statistical design or numeric input is scientifically invalid."""


PSEUDO_REPLICATION_UNITS = frozenset(
    {
        "seed",
        "seeds",
        "fold",
        "folds",
        "repeat",
        "repeats",
        "repeated_measure",
        "repeated_measures",
        "time_point",
        "time_points",
        "timepoint",
        "checkpoint",
        "checkpoints",
        "correlated_task",
        "correlated_tasks",
    }
)


class NullMethod(StrEnum):
    LABEL_PERMUTATION = "label_permutation"
    BLOCK_PERMUTATION = "block_permutation"
    WITHIN_CLUSTER_PERMUTATION = "within_cluster_permutation"
    SIGN_FLIP = "sign_flip"
    CIRCULAR_SHIFT = "circular_shift"
    PARAMETRIC = "parametric"


class MultiplicityMethod(StrEnum):
    BONFERRONI = "bonferroni"
    HOLM = "holm"
    BENJAMINI_HOCHBERG = "benjamini-hochberg"


@dataclass(frozen=True, slots=True)
class UnitObservation:
    """One measured value with explicit analysis and resampling identities."""

    value: float
    analysis_unit_id: str
    resampling_unit_id: str
    dependency_group_id: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.value, bool):
            raise StatisticalValidationError("observation value must not be boolean")
        try:
            numeric = float(self.value)
        except (TypeError, ValueError) as exc:
            raise StatisticalValidationError("observation value must be numeric") from exc
        if not math.isfinite(numeric):
            raise StatisticalValidationError("observation value must be finite")
        object.__setattr__(self, "value", numeric)
        for name in ("analysis_unit_id", "resampling_unit_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise StatisticalValidationError(f"{name} must be a non-empty string")
        if self.dependency_group_id is not None and (
            not isinstance(self.dependency_group_id, str) or not self.dependency_group_id.strip()
        ):
            raise StatisticalValidationError("dependency_group_id must be non-empty when present")


@dataclass(frozen=True, slots=True)
class StatisticalUnitDesign:
    unit_of_analysis: str
    resampling_unit: str
    observations: tuple[UnitObservation, ...]
    independence_justification: str
    repeated_measures: bool = False
    pseudo_unit_independence_justified: bool = False

    def __post_init__(self) -> None:
        for name in ("unit_of_analysis", "resampling_unit"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise StatisticalValidationError(f"{name} must be a non-empty string")
        if not isinstance(self.observations, tuple) or not self.observations:
            raise StatisticalValidationError("observations must be a non-empty tuple")
        if not all(isinstance(item, UnitObservation) for item in self.observations):
            raise StatisticalValidationError("observations must contain UnitObservation values")
        if not isinstance(self.independence_justification, str) or not self.independence_justification.strip():
            raise StatisticalValidationError("independence_justification must be explicit")
        if not isinstance(self.repeated_measures, bool) or not isinstance(
            self.pseudo_unit_independence_justified, bool
        ):
            raise StatisticalValidationError("unit-design flags must be boolean")


@dataclass(frozen=True, slots=True)
class UnitValidationReport:
    valid: bool
    independent_unit_count: int
    observation_count: int
    issues: tuple[str, ...]


def validate_statistical_units(
    design: StatisticalUnitDesign,
    *,
    raise_on_failure: bool = True,
) -> UnitValidationReport:
    """Validate independence and resampling at the declared statistical unit."""

    if not isinstance(design, StatisticalUnitDesign):
        raise StatisticalValidationError("expected StatisticalUnitDesign")
    issues: list[str] = []
    normalized_resampling = design.resampling_unit.strip().lower().replace(" ", "_").replace("-", "_")
    if normalized_resampling in PSEUDO_REPLICATION_UNITS and not design.pseudo_unit_independence_justified:
        issues.append(
            f"{design.resampling_unit!r} is normally a dependent pseudo-replication unit; "
            "an explicit design justification is required"
        )
    analysis_to_resampling: dict[str, set[str]] = {}
    dependency_to_resampling: dict[str, set[str]] = {}
    for observation in design.observations:
        analysis_to_resampling.setdefault(observation.analysis_unit_id, set()).add(
            observation.resampling_unit_id
        )
        if observation.dependency_group_id is not None:
            dependency_to_resampling.setdefault(observation.dependency_group_id, set()).add(
                observation.resampling_unit_id
            )
    split_analysis_units = {
        unit_id: values for unit_id, values in analysis_to_resampling.items() if len(values) > 1
    }
    if split_analysis_units:
        issues.append("the same analysis unit is split across multiple resampling units")
    split_dependency_groups = {
        group_id: values for group_id, values in dependency_to_resampling.items() if len(values) > 1
    }
    if split_dependency_groups:
        issues.append("dependent observations are split across multiple resampling units")
    has_repetition = len(analysis_to_resampling) < len(design.observations)
    if has_repetition and not design.repeated_measures:
        issues.append("repeated observations exist but repeated_measures is false")
    if design.repeated_measures:
        missing_groups = [
            observation.analysis_unit_id
            for observation in design.observations
            if observation.dependency_group_id is None
        ]
        if missing_groups:
            issues.append("repeated-measure observations require dependency_group_id")
    independent_units = {observation.resampling_unit_id for observation in design.observations}
    if len(independent_units) < 2:
        issues.append("at least two independent resampling units are required")
    report = UnitValidationReport(
        valid=not issues,
        independent_unit_count=len(independent_units),
        observation_count=len(design.observations),
        issues=tuple(issues),
    )
    if issues and raise_on_failure:
        raise StatisticalValidationError("invalid statistical units: " + "; ".join(issues))
    return report


validate_resampling_unit = validate_statistical_units


@dataclass(frozen=True, slots=True)
class DomainNullDesign:
    """Null mechanism plus the domain structure it must preserve."""

    name: str
    method: NullMethod
    exchangeability_unit: str
    required_preserved_structures: tuple[str, ...]
    preserved_structures: tuple[str, ...]
    exchangeability_justification: str
    labels_exchangeable: bool

    def __post_init__(self) -> None:
        for name in ("name", "exchangeability_unit", "exchangeability_justification"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise StatisticalValidationError(f"{name} must be a non-empty string")
        if not isinstance(self.method, NullMethod):
            try:
                object.__setattr__(self, "method", NullMethod(self.method))
            except (TypeError, ValueError) as exc:
                raise StatisticalValidationError("unknown domain-null method") from exc
        for name in ("required_preserved_structures", "preserved_structures"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or any(
                not isinstance(value, str) or not value.strip() for value in values
            ):
                raise StatisticalValidationError(f"{name} must be a tuple of non-empty strings")
        if not isinstance(self.labels_exchangeable, bool):
            raise StatisticalValidationError("labels_exchangeable must be boolean")


@dataclass(frozen=True, slots=True)
class NullValidationReport:
    valid: bool
    method: NullMethod
    issues: tuple[str, ...]


def validate_domain_null(
    null_design: DomainNullDesign,
    unit_design: StatisticalUnitDesign | None = None,
    *,
    raise_on_failure: bool = True,
) -> NullValidationReport:
    """Reject generic permutation where domain exchangeability is false."""

    if not isinstance(null_design, DomainNullDesign):
        raise StatisticalValidationError("expected DomainNullDesign")
    issues: list[str] = []
    missing = sorted(
        set(null_design.required_preserved_structures) - set(null_design.preserved_structures)
    )
    if missing:
        issues.append("null does not preserve required structure: " + ", ".join(missing))
    if null_design.method is NullMethod.LABEL_PERMUTATION and not null_design.labels_exchangeable:
        issues.append("generic label permutation is invalid because labels are not exchangeable")
    if null_design.method in {
        NullMethod.BLOCK_PERMUTATION,
        NullMethod.WITHIN_CLUSTER_PERMUTATION,
    } and not null_design.preserved_structures:
        issues.append("blocked permutation must name the preserved block/cluster structure")
    if unit_design is not None:
        validate_statistical_units(unit_design)
        if null_design.exchangeability_unit.strip().casefold() != unit_design.resampling_unit.strip().casefold():
            issues.append("null exchangeability unit does not match the resampling unit")
    report = NullValidationReport(not issues, null_design.method, tuple(issues))
    if issues and raise_on_failure:
        raise StatisticalValidationError("invalid domain-adaptive null: " + "; ".join(issues))
    return report


validate_exchangeability = validate_domain_null


def _finite_values(values: Iterable[float], field_name: str, *, minimum: int = 1) -> tuple[float, ...]:
    try:
        supplied = tuple(values)
    except (TypeError, ValueError) as exc:
        raise StatisticalValidationError(f"{field_name} must contain numeric values") from exc
    if any(isinstance(value, bool) for value in supplied):
        raise StatisticalValidationError(f"{field_name} values must not be boolean")
    try:
        result = tuple(float(value) for value in supplied)
    except (TypeError, ValueError) as exc:
        raise StatisticalValidationError(f"{field_name} must contain numeric values") from exc
    if len(result) < minimum:
        raise StatisticalValidationError(f"{field_name} requires at least {minimum} values")
    if any(not math.isfinite(value) for value in result):
        raise StatisticalValidationError(f"{field_name} values must be finite")
    return result


def mean_difference(treatment: Iterable[float], control: Iterable[float]) -> float:
    treatment_values = _finite_values(treatment, "treatment")
    control_values = _finite_values(control, "control")
    return fmean(treatment_values) - fmean(control_values)


def hedges_g(treatment: Iterable[float], control: Iterable[float]) -> float | None:
    """Bias-corrected standardized mean difference, or ``None`` at zero variance."""

    treatment_values = _finite_values(treatment, "treatment", minimum=2)
    control_values = _finite_values(control, "control", minimum=2)
    n_treatment, n_control = len(treatment_values), len(control_values)
    degrees_freedom = n_treatment + n_control - 2
    pooled_variance = (
        (n_treatment - 1) * stdev(treatment_values) ** 2
        + (n_control - 1) * stdev(control_values) ** 2
    ) / degrees_freedom
    if pooled_variance == 0:
        return None
    correction = 1 - 3 / (4 * degrees_freedom - 1) if degrees_freedom > 1 else 1.0
    return correction * mean_difference(treatment_values, control_values) / math.sqrt(pooled_variance)


def _quantile(sorted_values: Sequence[float], probability: float) -> float:
    if not sorted_values:
        raise StatisticalValidationError("cannot take a quantile of no values")
    position = (len(sorted_values) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    fraction = position - lower
    return sorted_values[lower] * (1 - fraction) + sorted_values[upper] * fraction


def bootstrap_mean_difference_ci(
    treatment: Iterable[float],
    control: Iterable[float],
    *,
    confidence_level: float = 0.95,
    resamples: int = 2000,
    seed: int = 0,
) -> tuple[float, float]:
    """Deterministic percentile bootstrap over independent supplied units."""

    treatment_values = _finite_values(treatment, "treatment", minimum=2)
    control_values = _finite_values(control, "control", minimum=2)
    if isinstance(confidence_level, bool) or not isinstance(confidence_level, (int, float)):
        raise StatisticalValidationError("confidence_level must be numeric")
    if not math.isfinite(confidence_level) or not 0 < confidence_level < 1:
        raise StatisticalValidationError("confidence_level must lie between zero and one")
    if isinstance(resamples, bool) or not isinstance(resamples, int) or resamples < 100:
        raise StatisticalValidationError("resamples must be an integer of at least 100")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise StatisticalValidationError("seed must be an integer")
    generator = random.Random(seed)
    estimates: list[float] = []
    for _ in range(resamples):
        treatment_sample = generator.choices(treatment_values, k=len(treatment_values))
        control_sample = generator.choices(control_values, k=len(control_values))
        estimates.append(fmean(treatment_sample) - fmean(control_sample))
    estimates.sort()
    tail = (1 - confidence_level) / 2
    return _quantile(estimates, tail), _quantile(estimates, 1 - tail)


def permutation_test_mean_difference(
    treatment: Iterable[float],
    control: Iterable[float],
    *,
    alternative: str = "two-sided",
    resamples: int = 5000,
    seed: int = 0,
    exact_limit: int = 50_000,
) -> float:
    """Permutation p-value for exchangeable independent units.

    Callers must validate domain exchangeability before selecting this generic
    label permutation.  Exact enumeration is used when the family is small;
    otherwise a fixed-seed Monte Carlo estimate with the plus-one correction is
    returned.
    """

    treatment_values = _finite_values(treatment, "treatment")
    control_values = _finite_values(control, "control")
    if alternative not in {"two-sided", "greater", "less"}:
        raise StatisticalValidationError("alternative must be two-sided, greater, or less")
    if isinstance(resamples, bool) or not isinstance(resamples, int) or resamples < 100:
        raise StatisticalValidationError("resamples must be an integer of at least 100")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise StatisticalValidationError("seed must be an integer")
    if isinstance(exact_limit, bool) or not isinstance(exact_limit, int) or exact_limit < 1:
        raise StatisticalValidationError("exact_limit must be a positive integer")
    combined = treatment_values + control_values
    treatment_count = len(treatment_values)
    observed = mean_difference(treatment_values, control_values)

    def at_least_as_extreme(value: float) -> bool:
        tolerance = 1e-15
        if alternative == "two-sided":
            return abs(value) >= abs(observed) - tolerance
        if alternative == "greater":
            return value >= observed - tolerance
        return value <= observed + tolerance

    permutation_count = math.comb(len(combined), treatment_count)
    if permutation_count <= exact_limit:
        extreme = 0
        indexes = range(len(combined))
        for treatment_indexes in itertools.combinations(indexes, treatment_count):
            selected = set(treatment_indexes)
            permuted_treatment = [combined[index] for index in indexes if index in selected]
            permuted_control = [combined[index] for index in indexes if index not in selected]
            if at_least_as_extreme(mean_difference(permuted_treatment, permuted_control)):
                extreme += 1
        return extreme / permutation_count
    generator = random.Random(seed)
    extreme = 0
    shuffled = list(combined)
    for _ in range(resamples):
        generator.shuffle(shuffled)
        value = mean_difference(shuffled[:treatment_count], shuffled[treatment_count:])
        if at_least_as_extreme(value):
            extreme += 1
    return (extreme + 1) / (resamples + 1)


@dataclass(frozen=True, slots=True)
class EffectEstimate:
    estimand: str
    estimate: float
    standardized_effect: float | None
    standard_error: float
    confidence_level: float
    ci_lower: float
    ci_upper: float
    uncertainty_method: str
    p_value: float
    test_method: str
    treatment_independent_units: int
    control_independent_units: int

    def __post_init__(self) -> None:
        if not isinstance(self.estimand, str) or not self.estimand.strip():
            raise StatisticalValidationError("estimand must be non-empty")
        numeric = (self.estimate, self.standard_error, self.ci_lower, self.ci_upper, self.p_value)
        if any(not math.isfinite(value) for value in numeric):
            raise StatisticalValidationError("effect-estimate values must be finite")
        if self.standardized_effect is not None and not math.isfinite(self.standardized_effect):
            raise StatisticalValidationError("standardized effect must be finite when present")
        if self.ci_lower > self.ci_upper:
            raise StatisticalValidationError("confidence interval bounds are reversed")
        if (
            isinstance(self.confidence_level, bool)
            or not isinstance(self.confidence_level, (int, float))
            or not math.isfinite(self.confidence_level)
            or not 0 < self.confidence_level < 1
        ):
            raise StatisticalValidationError("confidence_level must lie between zero and one")
        if not 0 <= self.p_value <= 1:
            raise StatisticalValidationError("p_value must be between zero and one")
        for name in ("treatment_independent_units", "control_independent_units"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 2:
                raise StatisticalValidationError(f"{name} must be an integer of at least two")
        for name in ("uncertainty_method", "test_method"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise StatisticalValidationError(f"{name} must be non-empty")


def analyze_two_group(
    treatment: Iterable[float],
    control: Iterable[float],
    *,
    confidence_level: float = 0.95,
    bootstrap_resamples: int = 2000,
    permutation_resamples: int = 5000,
    alternative: str = "two-sided",
    seed: int = 0,
) -> EffectEstimate:
    """Return effect size, uncertainty, and a permutation p-value together."""

    treatment_values = _finite_values(treatment, "treatment", minimum=2)
    control_values = _finite_values(control, "control", minimum=2)
    estimate = mean_difference(treatment_values, control_values)
    lower, upper = bootstrap_mean_difference_ci(
        treatment_values,
        control_values,
        confidence_level=confidence_level,
        resamples=bootstrap_resamples,
        seed=seed,
    )
    standard_error = math.sqrt(
        stdev(treatment_values) ** 2 / len(treatment_values)
        + stdev(control_values) ** 2 / len(control_values)
    )
    p_value = permutation_test_mean_difference(
        treatment_values,
        control_values,
        alternative=alternative,
        resamples=permutation_resamples,
        seed=seed,
    )
    return EffectEstimate(
        estimand="difference in arithmetic means (treatment - control)",
        estimate=estimate,
        standardized_effect=hedges_g(treatment_values, control_values),
        standard_error=standard_error,
        confidence_level=confidence_level,
        ci_lower=lower,
        ci_upper=upper,
        uncertainty_method=f"percentile bootstrap over independent units ({bootstrap_resamples} resamples)",
        p_value=p_value,
        test_method="exchangeable-unit label permutation",
        treatment_independent_units=len(treatment_values),
        control_independent_units=len(control_values),
    )


@dataclass(frozen=True, slots=True)
class MultiplicityResult:
    hypothesis_id: str
    raw_p_value: float
    adjusted_p_value: float
    rejected: bool
    method: MultiplicityMethod
    family_size: int


def _validate_p_values(p_values: Sequence[float]) -> tuple[float, ...]:
    try:
        supplied = tuple(p_values)
    except (TypeError, ValueError) as exc:
        raise StatisticalValidationError("p-values must be numeric") from exc
    if any(isinstance(value, bool) for value in supplied):
        raise StatisticalValidationError("p-values must not be boolean")
    try:
        values = tuple(float(value) for value in supplied)
    except (TypeError, ValueError) as exc:
        raise StatisticalValidationError("p-values must be numeric") from exc
    if not values:
        raise StatisticalValidationError("p-value family must not be empty")
    if any(not math.isfinite(value) or not 0 <= value <= 1 for value in values):
        raise StatisticalValidationError("p-values must lie between zero and one")
    return values


def adjust_pvalues(
    p_values: Sequence[float],
    *,
    method: MultiplicityMethod | str,
    alpha: float = 0.05,
    hypothesis_ids: Sequence[str] | None = None,
) -> tuple[MultiplicityResult, ...]:
    """Apply Bonferroni, Holm FWER, or Benjamini-Hochberg FDR correction."""

    values = _validate_p_values(p_values)
    try:
        selected_method = method if isinstance(method, MultiplicityMethod) else MultiplicityMethod(method)
    except (TypeError, ValueError) as exc:
        raise StatisticalValidationError("a recognized multiplicity correction is required") from exc
    if isinstance(alpha, bool) or not isinstance(alpha, (int, float)):
        raise StatisticalValidationError("alpha must be numeric")
    if not math.isfinite(alpha) or not 0 < alpha < 1:
        raise StatisticalValidationError("alpha must lie between zero and one")
    if hypothesis_ids is None:
        identifiers = tuple(f"H{index + 1}" for index in range(len(values)))
    else:
        identifiers = tuple(hypothesis_ids)
        if len(identifiers) != len(values):
            raise StatisticalValidationError("hypothesis_ids and p_values must have equal length")
        if any(not isinstance(value, str) or not value.strip() for value in identifiers):
            raise StatisticalValidationError("hypothesis IDs must be non-empty strings")
        if len(set(identifiers)) != len(identifiers):
            raise StatisticalValidationError("hypothesis IDs must be unique")
    family_size = len(values)
    adjusted = [0.0] * family_size
    if selected_method is MultiplicityMethod.BONFERRONI:
        adjusted = [min(1.0, value * family_size) for value in values]
    elif selected_method is MultiplicityMethod.HOLM:
        order = sorted(range(family_size), key=values.__getitem__)
        running = 0.0
        for rank, index in enumerate(order):
            running = max(running, (family_size - rank) * values[index])
            adjusted[index] = min(1.0, running)
    else:
        order = sorted(range(family_size), key=values.__getitem__, reverse=True)
        running = 1.0
        for descending_rank, index in enumerate(order):
            ascending_rank = family_size - descending_rank
            running = min(running, values[index] * family_size / ascending_rank)
            adjusted[index] = min(1.0, running)
    return tuple(
        MultiplicityResult(
            hypothesis_id=identifiers[index],
            raw_p_value=values[index],
            adjusted_p_value=adjusted[index],
            rejected=adjusted[index] <= alpha,
            method=selected_method,
            family_size=family_size,
        )
        for index in range(family_size)
    )


adjust_p_values = adjust_pvalues


def validate_multiplicity_plan(
    *,
    family_size: int,
    method: MultiplicityMethod | str | None,
) -> MultiplicityMethod | None:
    """Require a declared correction whenever more than one claim is tested."""

    if isinstance(family_size, bool) or not isinstance(family_size, int) or family_size < 1:
        raise StatisticalValidationError("family_size must be a positive integer")
    if family_size == 1 and method is None:
        return None
    if method is None or str(method).strip().lower() in {"none", "unadjusted", "naive"}:
        raise StatisticalValidationError("multiple hypotheses require a correction plan")
    try:
        return method if isinstance(method, MultiplicityMethod) else MultiplicityMethod(method)
    except (TypeError, ValueError) as exc:
        raise StatisticalValidationError("unknown multiplicity correction") from exc


@dataclass(frozen=True, slots=True)
class StatisticalAudit:
    unit_report: UnitValidationReport
    null_report: NullValidationReport
    effect: EffectEstimate
    multiplicity: tuple[MultiplicityResult, ...]

    @property
    def valid(self) -> bool:
        return self.unit_report.valid and self.null_report.valid and bool(self.multiplicity)


__all__ = [
    "StatisticalValidationError",
    "PSEUDO_REPLICATION_UNITS",
    "NullMethod",
    "MultiplicityMethod",
    "UnitObservation",
    "StatisticalUnitDesign",
    "UnitValidationReport",
    "validate_statistical_units",
    "validate_resampling_unit",
    "DomainNullDesign",
    "NullValidationReport",
    "validate_domain_null",
    "validate_exchangeability",
    "mean_difference",
    "hedges_g",
    "bootstrap_mean_difference_ci",
    "permutation_test_mean_difference",
    "EffectEstimate",
    "analyze_two_group",
    "MultiplicityResult",
    "adjust_pvalues",
    "adjust_p_values",
    "validate_multiplicity_plan",
    "StatisticalAudit",
]
