"""Pure, non-authoritative fixed-complete bounded-mean numerical procedure.

This is a NEW prospective profile, not a reinterpretation of any bootstrap
profile.  Let D_i be candidate minus reference correctness, averaged over the
same frozen S seeds for row i.  Its exact numerator is an integer and its
known support is [-1, 1].  Conditional on the fixed models, training data,
seed set and protocol, the required scope is independent rows sampled from a
common population, with fixed complete n and one prospectively chosen mean
comparison.  Seeds are not independent units.  There is no optional stopping,
post-outcome selection, missing-row exclusion or repeated-comparison guarantee.

For mean mu = E[D], Hoeffding gives P(|D_bar - mu| >= r) <= alpha for
r = sqrt(2 * ln(2 / alpha) / n).  Intersecting [D_bar-r, D_bar+r] with the
known support preserves coverage of at least 1-alpha.  The separate mean-zero
p bound is min(1, 2 * exp(-n * D_bar**2 / 2)); it tests mu=0, not a margin.
All mean decisions use the same interval, so they are covered by its single
error event.  Equivalence means strictly within the frozen margins, NOT zero.

The auxiliary conditional sign test instead tests
P(D>0 | D!=0)=1/2.  It assumes independent common-population rows too.  Ties
are removed only from its explicitly reported denominator, never from the
mean.  All ties make that conditional estimand unobserved and the test not
testable (conventional p=1).  Its p-value never drives a mean decision; this
module makes no joint mean/sign or multiple-comparison error-rate claim.

Alpha and margins mean their EXACT binary64 input values, not the original
decimal text that a caller may have rounded into them.  Integral numeric
scalars are converted to binary64; bool and other numeric types are rejected.
Inputs must be frozen prospectively by an external owner.  Counts, seed_count
and an ordered grid DO NOT prove execution, per-seed completeness, sampling
independence, common-population scope, custody or prospective timing.  A
consumer must derive counts from exact ordered, verified projection pairs and
replay those scientific/custody joins.  This module has no issuer or cache.

Numerical enclosure relies on Python's documented correctly rounded Decimal
arithmetic.  Fresh precision-80 directed contexts enclose rational operations.
Decimal ln/sqrt/exp ignore ordinary directed rounding and round to nearest;
one Decimal next_plus after each supplies an upper bound, with monotonicity
propagating bounds.  Final binary64 conversion is checked against the exact
Decimal/rational bound and stepped outward, not adjusted by an epsilon.
Decimal exponents are wide enough for this profile (the smallest mean p is
2*exp(-2048)).  A positive p below binary64 range is reported as an upper
bound at the smallest positive subnormal, never zero; log bounds remain
available.  These are conservative enclosures, not correctly-rounded exact
answers or a formal verification of Python's arithmetic implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from decimal import (
    Context,
    Decimal,
    DivisionByZero,
    InvalidOperation,
    Overflow,
    ROUND_CEILING,
    ROUND_FLOOR,
)
from enum import StrEnum
from fractions import Fraction
import math

from .errors import ValidationError
from .models import validate_identifier


BOUNDED_MEAN_SCHEMA = "fixed-complete-bounded-mean-numeric/v1"
BOUNDED_MEAN_PLAN_SCHEMA = "fixed-complete-bounded-mean-plan/v1"
BOUNDED_MEAN_PROFILE_ID = "independent-row-fixed-seed-micro-accuracy-hoeffding/v1"
BOUNDED_MEAN_PROCEDURE_ID = "fixed-complete-bounded-mean-hoeffding/v1"
BOUNDED_MEAN_INTERVAL_METHOD_ID = "two-sided-hoeffding-known-support/v1"
BOUNDED_MEAN_ZERO_P_METHOD_ID = "two-sided-hoeffding-mean-zero-upper-bound/v1"
BOUNDED_MEAN_DECISION_RULE_ID = "ordered-frozen-margin-bounded-mean/v1"
BOUNDED_MEAN_SIGN_METHOD_ID = "conditional-nonzero-exact-two-sided-sign/v1"
BOUNDED_MEAN_SCALAR_CONTRACT_ID = "exact-binary64-input/v1"
BOUNDED_MEAN_NUMERICAL_CONTRACT_ID = "decimal80-directed-outward-binary64/v1"
BOUNDED_MEAN_CONDITIONAL_SCOPE = (
    "INDEPENDENT_COMMON_POPULATION_ROWS_CONDITIONAL_ON_FIXED_MODELS_"
    "TRAINING_DATA_SEED_SET_AND_PROTOCOL"
)
# Deliberately bounded by scientific_design.MAX_CHECKED_SUPERIORITY_UNITS and
# generic_ml_projection.MAX_GENERIC_ML_SEEDS, without importing either issuer.
MAX_BOUNDED_MEAN_UNITS = 4096
MAX_BOUNDED_MEAN_SEEDS = 24
_DECIMAL_PRECISION = 80


class BoundedMeanInferenceError(ValidationError):
    """The closed bounded-mean numeric input is invalid or incomplete."""


class BoundedMeanDecision(StrEnum):
    FALSIFIED = "FALSIFIED"
    SUPPORTED = "SUPPORTED"
    EQUIVALENT_WITHIN_MARGINS = "EQUIVALENT_WITHIN_MARGINS"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    NEGATIVE = "NEGATIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


class BoundedMeanDecisionReason(StrEnum):
    MEANINGFUL_HARM = "MEANINGFUL_HARM"
    MEANINGFUL_BENEFIT = "MEANINGFUL_BENEFIT"
    STRICT_MARGIN_EQUIVALENCE = "STRICT_MARGIN_EQUIVALENCE"
    POSITIVE_WITHOUT_ESTABLISHED_BENEFIT_MARGIN = (
        "POSITIVE_WITHOUT_ESTABLISHED_BENEFIT_MARGIN"
    )
    NEGATIVE_WITHOUT_ESTABLISHED_HARM_MARGIN = (
        "NEGATIVE_WITHOUT_ESTABLISHED_HARM_MARGIN"
    )
    MINIMUM_SIZE_NOT_MET = "MINIMUM_SIZE_NOT_MET"
    INTERVAL_UNRESOLVED = "INTERVAL_UNRESOLVED"


class ConditionalSignStatus(StrEnum):
    TESTABLE = "TESTABLE"
    ALL_TIES_NOT_TESTABLE = "ALL_TIES_NOT_TESTABLE"


def _integer(value: object, label: str, *, low: int, high: int | None = None) -> int:
    if type(value) is not int or value < low or (high is not None and value > high):
        bound = f"{low}..{high}" if high is not None else f">={low}"
        raise BoundedMeanInferenceError(f"{label} must be an integer in {bound}")
    return value


def _binary64(value: object, label: str) -> float:
    if type(value) not in (int, float):
        raise BoundedMeanInferenceError(f"{label} must be an int or float, not bool")
    try:
        converted = float(value)
    except (OverflowError, ValueError) as exc:
        raise BoundedMeanInferenceError(f"{label} must be finite binary64") from exc
    if not math.isfinite(converted):
        raise BoundedMeanInferenceError(f"{label} must be finite binary64")
    return converted


def _unit_id(value: object) -> str:
    if type(value) is not str:
        raise BoundedMeanInferenceError("unit_id must be a string identifier")
    try:
        return validate_identifier(value, "bounded-mean unit_id")
    except ValidationError as exc:
        raise BoundedMeanInferenceError(str(exc)) from exc


@dataclass(frozen=True, slots=True)
class BoundedMeanInferencePlan:
    """A numeric plan declaration; possession is not proof it was prospective.

    minimum_unit_count may exceed this fixed grid's size: the complete grid
    then yields a retained INCONCLUSIVE result, never permission to collect
    more rows after observing this result.  A missing grid row is an error.
    """

    alpha: float
    benefit_margin: float
    harm_margin: float
    minimum_unit_count: int
    unit_ids: tuple[str, ...]
    seed_order: tuple[int, ...]
    support_low: float = -1.0
    support_high: float = 1.0

    def __post_init__(self) -> None:
        for name in (
            "alpha",
            "benefit_margin",
            "harm_margin",
            "support_low",
            "support_high",
        ):
            object.__setattr__(self, name, _binary64(getattr(self, name), name))
        if not 0 < self.alpha < 1:
            raise BoundedMeanInferenceError(
                "alpha must be strictly between zero and one"
            )
        if not 0 < self.benefit_margin <= 1 or not 0 < self.harm_margin <= 1:
            raise BoundedMeanInferenceError(
                "frozen margins must be positive and at most one"
            )
        if (self.support_low, self.support_high) != (-1.0, 1.0):
            raise BoundedMeanInferenceError(
                "the prospective support must be exactly [-1, 1]"
            )
        _integer(
            self.minimum_unit_count,
            "minimum_unit_count",
            low=1,
            high=MAX_BOUNDED_MEAN_UNITS,
        )
        if (
            type(self.unit_ids) is not tuple
            or not 1 <= len(self.unit_ids) <= MAX_BOUNDED_MEAN_UNITS
        ):
            raise BoundedMeanInferenceError(
                "unit_ids must be a nonempty tuple of at most 4096 rows"
            )
        for value in self.unit_ids:
            _unit_id(value)
        if len(set(self.unit_ids)) != len(self.unit_ids):
            raise BoundedMeanInferenceError(
                "unit_ids must be unique and ordered prospectively"
            )
        if (
            type(self.seed_order) is not tuple
            or not 1 <= len(self.seed_order) <= MAX_BOUNDED_MEAN_SEEDS
        ):
            raise BoundedMeanInferenceError(
                "seed_order must be a nonempty tuple of at most 24 seeds"
            )
        for value in self.seed_order:
            _integer(value, "seed", low=0)
        if len(set(self.seed_order)) != len(self.seed_order):
            raise BoundedMeanInferenceError("seed_order must contain unique seeds")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": BOUNDED_MEAN_PLAN_SCHEMA,
            "profile_id": BOUNDED_MEAN_PROFILE_ID,
            "scalar_contract_id": BOUNDED_MEAN_SCALAR_CONTRACT_ID,
            "alpha": self.alpha,
            "benefit_margin": self.benefit_margin,
            "harm_margin": self.harm_margin,
            "minimum_unit_count": self.minimum_unit_count,
            "unit_ids": list(self.unit_ids),
            "seed_order": list(self.seed_order),
            "support_low": self.support_low,
            "support_high": self.support_high,
        }


@dataclass(frozen=True, slots=True)
class PairedRowCorrectnessCounts:
    """Exact row totals, to be derived externally from all ordered seed pairs.

    Matching seed_count is a numeric consistency check, NOT an execution or
    per-seed completeness attestation.  Marginal correctness totals suffice
    for D_i but cannot reconstruct or authenticate the underlying seed pairs.
    """

    unit_id: str
    seed_count: int
    candidate_correct_count: int
    reference_correct_count: int

    def __post_init__(self) -> None:
        _unit_id(self.unit_id)
        _integer(self.seed_count, "seed_count", low=1, high=MAX_BOUNDED_MEAN_SEEDS)
        for name in ("candidate_correct_count", "reference_correct_count"):
            _integer(getattr(self, name), name, low=0, high=self.seed_count)

    def to_dict(self) -> dict[str, object]:
        return {
            "unit_id": self.unit_id,
            "seed_count": self.seed_count,
            "candidate_correct_count": self.candidate_correct_count,
            "reference_correct_count": self.reference_correct_count,
        }


def _context(rounding: str) -> Context:
    # No ambient decimal precision, rounding, exponent bounds, traps or flags.
    return Context(
        prec=_DECIMAL_PRECISION,
        rounding=rounding,
        Emin=-999999,
        Emax=999999,
        capitals=1,
        clamp=0,
        flags=[],
        traps=[InvalidOperation, DivisionByZero, Overflow],
    )


def _float_outward(value: Decimal | Fraction, *, upper: bool) -> float:
    """Compare exact representations after conversion, never a tolerance."""
    result = float(value)
    if not math.isfinite(result):
        raise BoundedMeanInferenceError("numeric enclosure exceeded binary64 range")
    exact = Decimal.from_float if isinstance(value, Decimal) else Fraction.from_float
    direction = math.inf if upper else -math.inf
    while (exact(result) < value) if upper else (exact(result) > value):
        result = math.nextafter(result, direction)
    return result


@dataclass(frozen=True, slots=True)
class ConditionalSignResult:
    """Auxiliary exact conditional sign test, with no mean-decision authority."""

    positive_count: int
    negative_count: int
    tie_count: int
    non_tied_count: int = field(init=False)
    status: ConditionalSignStatus = field(init=False)
    p_numerator: int = field(init=False)
    p_denominator: int = field(init=False)
    p_value_upper: float = field(init=False)
    binary64_underflow_limited: bool = field(init=False)

    def __post_init__(self) -> None:
        for name in ("positive_count", "negative_count", "tie_count"):
            _integer(getattr(self, name), name, low=0, high=MAX_BOUNDED_MEAN_UNITS)
        non_tied = self.positive_count + self.negative_count
        if not 1 <= non_tied + self.tie_count <= MAX_BOUNDED_MEAN_UNITS:
            raise BoundedMeanInferenceError("sign counts must total 1..4096 rows")
        denominator = 1 << non_tied
        smaller = min(self.positive_count, self.negative_count)
        term = tail = 1
        for index in range(1, smaller + 1):
            term = term * (non_tied - index + 1) // index
            tail += term
        exact_p = Fraction(min(denominator, 2 * tail), denominator)
        object.__setattr__(self, "non_tied_count", non_tied)
        object.__setattr__(
            self,
            "status",
            ConditionalSignStatus.TESTABLE
            if non_tied
            else ConditionalSignStatus.ALL_TIES_NOT_TESTABLE,
        )
        object.__setattr__(self, "p_numerator", exact_p.numerator)
        object.__setattr__(self, "p_denominator", exact_p.denominator)
        object.__setattr__(self, "p_value_upper", _float_outward(exact_p, upper=True))
        object.__setattr__(
            self,
            "binary64_underflow_limited",
            exact_p < Fraction.from_float(math.ulp(0.0)),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "method_id": BOUNDED_MEAN_SIGN_METHOD_ID,
            "estimand": "P(D>0 | D!=0)",
            "null": "P(D>0 | D!=0)=1/2",
            "role": "AUXILIARY_ONLY_NO_MEAN_DECISION_OR_JOINT_ERROR_CONTROL",
            "positive_count": self.positive_count,
            "negative_count": self.negative_count,
            "tie_count": self.tie_count,
            "non_tied_count": self.non_tied_count,
            "status": self.status.value,
            "p_numerator": self.p_numerator,
            "p_denominator": self.p_denominator,
            "p_value_upper": self.p_value_upper,
            "binary64_underflow_limited": self.binary64_underflow_limited,
        }


def _mean_decision(
    plan: BoundedMeanInferencePlan,
    low: float,
    high: float,
) -> tuple[BoundedMeanDecision, BoundedMeanDecisionReason]:
    if len(plan.unit_ids) < plan.minimum_unit_count:
        return (
            BoundedMeanDecision.INCONCLUSIVE,
            BoundedMeanDecisionReason.MINIMUM_SIZE_NOT_MET,
        )
    if high <= -plan.harm_margin:
        return BoundedMeanDecision.FALSIFIED, BoundedMeanDecisionReason.MEANINGFUL_HARM
    if low >= plan.benefit_margin:
        return (
            BoundedMeanDecision.SUPPORTED,
            BoundedMeanDecisionReason.MEANINGFUL_BENEFIT,
        )
    if low > -plan.harm_margin and high < plan.benefit_margin:
        return (
            BoundedMeanDecision.EQUIVALENT_WITHIN_MARGINS,
            BoundedMeanDecisionReason.STRICT_MARGIN_EQUIVALENCE,
        )
    if low > 0:
        return (
            BoundedMeanDecision.PARTIALLY_SUPPORTED,
            BoundedMeanDecisionReason.POSITIVE_WITHOUT_ESTABLISHED_BENEFIT_MARGIN,
        )
    if high < 0:
        return (
            BoundedMeanDecision.NEGATIVE,
            BoundedMeanDecisionReason.NEGATIVE_WITHOUT_ESTABLISHED_HARM_MARGIN,
        )
    return (
        BoundedMeanDecision.INCONCLUSIVE,
        BoundedMeanDecisionReason.INTERVAL_UNRESOLVED,
    )


@dataclass(frozen=True, slots=True)
class BoundedMeanInferenceResult:
    """Immutable numeric DTO.  Derived values cannot be supplied to its init.

    No field asserts independence approval or production acceptance.  This
    DTO and its serialization are caller-reproducible numerical output only.
    """

    plan: BoundedMeanInferencePlan
    rows: tuple[PairedRowCorrectnessCounts, ...]
    row_effect_numerators: tuple[int, ...] = field(init=False)
    row_effect_denominator: int = field(init=False)
    mean_numerator: int = field(init=False)
    mean_denominator: int = field(init=False)
    mean_estimate: float = field(init=False)
    confidence_level_lower: float = field(init=False)
    radius_upper: float = field(init=False)
    confidence_low: float = field(init=False)
    confidence_high: float = field(init=False)
    mean_zero_p_upper: float = field(init=False)
    mean_zero_log_p_upper: float = field(init=False)
    mean_zero_p_binary64_underflow_limited: bool = field(init=False)
    auxiliary_sign: ConditionalSignResult = field(init=False)
    decision: BoundedMeanDecision = field(init=False)
    decision_reason: BoundedMeanDecisionReason = field(init=False)

    def __post_init__(self) -> None:
        if type(self.plan) is not BoundedMeanInferencePlan:
            raise BoundedMeanInferenceError("plan must be a BoundedMeanInferencePlan")
        if (
            type(self.rows) is not tuple
            or not 1 <= len(self.rows) <= MAX_BOUNDED_MEAN_UNITS
        ):
            raise BoundedMeanInferenceError(
                "rows must be a nonempty tuple of at most 4096 rows"
            )
        if any(type(row) is not PairedRowCorrectnessCounts for row in self.rows):
            raise BoundedMeanInferenceError(
                "rows must contain only PairedRowCorrectnessCounts"
            )
        # Revalidate owned copies; a nominally frozen caller DTO is not itself
        # authority or a reason to skip the numerical input boundary.
        object.__setattr__(self, "plan", replace(self.plan))
        object.__setattr__(self, "rows", tuple(replace(row) for row in self.rows))
        if tuple(row.unit_id for row in self.rows) != self.plan.unit_ids:
            raise BoundedMeanInferenceError(
                "rows must exactly match the ordered complete planned grid"
            )
        seed_count = len(self.plan.seed_order)
        if any(row.seed_count != seed_count for row in self.rows):
            raise BoundedMeanInferenceError(
                "each row must declare the exact planned seed count"
            )

        differences = tuple(
            row.candidate_correct_count - row.reference_correct_count
            for row in self.rows
        )
        count = len(differences)
        numerator, denominator = sum(differences), count * seed_count
        up, down = _context(ROUND_CEILING), _context(ROUND_FLOOR)
        alpha = Decimal.from_float(self.plan.alpha)
        two, zero = Decimal(2), Decimal(0)
        ratio_upper = up.divide(two, alpha)
        log_ratio_upper = up.ln(ratio_upper).next_plus(context=up)
        square_upper = up.divide(up.multiply(two, log_ratio_upper), Decimal(count))
        radius_upper = up.sqrt(square_upper).next_plus(context=up)
        mean_low = down.divide(Decimal(numerator), Decimal(denominator))
        mean_high = up.divide(Decimal(numerator), Decimal(denominator))
        low = _float_outward(
            max(Decimal(-1), down.subtract(mean_low, radius_upper)), upper=False
        )
        high = _float_outward(
            min(Decimal(1), up.add(mean_high, radius_upper)), upper=True
        )

        # Exact exponent -n * D_bar^2 / 2 before directed Decimal division.
        exponent_upper = up.divide(
            Decimal(-(numerator * numerator)),
            Decimal(2 * count * seed_count * seed_count),
        )
        log_two_upper = up.ln(two).next_plus(context=up)
        log_p_upper = min(zero, up.add(log_two_upper, exponent_upper))
        p_upper = min(Decimal(1), up.exp(log_p_upper).next_plus(context=up))
        decision, reason = _mean_decision(self.plan, low, high)
        values = {
            "row_effect_numerators": differences,
            "row_effect_denominator": seed_count,
            "mean_numerator": numerator,
            "mean_denominator": denominator,
            "mean_estimate": float(Fraction(numerator, denominator)),
            "confidence_level_lower": _float_outward(
                down.subtract(Decimal(1), alpha), upper=False
            ),
            "radius_upper": _float_outward(radius_upper, upper=True),
            "confidence_low": low,
            "confidence_high": high,
            "mean_zero_p_upper": _float_outward(p_upper, upper=True),
            "mean_zero_log_p_upper": _float_outward(log_p_upper, upper=True),
            "mean_zero_p_binary64_underflow_limited": p_upper
            < Decimal.from_float(math.ulp(0.0)),
            "auxiliary_sign": ConditionalSignResult(
                positive_count=sum(value > 0 for value in differences),
                negative_count=sum(value < 0 for value in differences),
                tie_count=sum(value == 0 for value in differences),
            ),
            "decision": decision,
            "decision_reason": reason,
        }
        for name, value in values.items():
            object.__setattr__(self, name, value)

    def to_dict(self) -> dict[str, object]:
        """A fresh closed mapping, not a serialized scientific authority."""
        return {
            "schema": BOUNDED_MEAN_SCHEMA,
            "profile_id": BOUNDED_MEAN_PROFILE_ID,
            "procedure_id": BOUNDED_MEAN_PROCEDURE_ID,
            "interval_method_id": BOUNDED_MEAN_INTERVAL_METHOD_ID,
            "mean_zero_p_method_id": BOUNDED_MEAN_ZERO_P_METHOD_ID,
            "decision_rule_id": BOUNDED_MEAN_DECISION_RULE_ID,
            "numerical_contract_id": BOUNDED_MEAN_NUMERICAL_CONTRACT_ID,
            "conditional_scope": BOUNDED_MEAN_CONDITIONAL_SCOPE,
            "materialization_scope": "PURE_NON_AUTHORITATIVE_NUMERIC",
            "mean_estimand": "E[D]",
            "mean_zero_null": "E[D]=0",
            "plan": self.plan.to_dict(),
            "rows": [row.to_dict() for row in self.rows],
            "unit_count": len(self.rows),
            "row_effect_numerators": list(self.row_effect_numerators),
            "row_effect_denominator": self.row_effect_denominator,
            "mean_numerator": self.mean_numerator,
            "mean_denominator": self.mean_denominator,
            "mean_estimate": self.mean_estimate,
            "confidence_level_lower": self.confidence_level_lower,
            "radius_upper": self.radius_upper,
            "confidence_low": self.confidence_low,
            "confidence_high": self.confidence_high,
            "mean_zero_p_upper": self.mean_zero_p_upper,
            "mean_zero_log_p_upper": self.mean_zero_log_p_upper,
            "mean_zero_p_binary64_underflow_limited": self.mean_zero_p_binary64_underflow_limited,
            "auxiliary_sign": self.auxiliary_sign.to_dict(),
            "decision": self.decision.value,
            "decision_reason": self.decision_reason.value,
        }


def analyze_fixed_complete_bounded_mean(
    *,
    plan: BoundedMeanInferencePlan,
    rows: tuple[PairedRowCorrectnessCounts, ...],
) -> BoundedMeanInferenceResult:
    """Compute numerical output only; no artifact, ledger or authority write."""
    return BoundedMeanInferenceResult(plan=plan, rows=rows)
