"""Finite numerical/DTO checks, never production scientific acceptance.

The independent enclosure oracle avoids Decimal ln/sqrt/exp: logarithms use
an exact rational atanh series with a geometric remainder, square roots use
integer isqrt at 120 decimal places, and exponentials use an alternating
rational Taylor enclosure followed by 12 directed precision-200 squarings.
These implementation checks complement, not replace, the mathematical bound
or the consumer's untested sampling/prospective/custody obligations.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
from decimal import (
    Context,
    Decimal,
    Inexact,
    ROUND_CEILING,
    ROUND_DOWN,
    ROUND_FLOOR,
    localcontext,
)
from fractions import Fraction
import json
import math
import unittest

from scientist_one.bounded_mean_inference import (
    BOUNDED_MEAN_DECISION_RULE_ID,
    BOUNDED_MEAN_INTERVAL_METHOD_ID,
    BOUNDED_MEAN_NUMERICAL_CONTRACT_ID,
    BOUNDED_MEAN_PLAN_SCHEMA,
    BOUNDED_MEAN_PROCEDURE_ID,
    BOUNDED_MEAN_PROFILE_ID,
    BOUNDED_MEAN_SCALAR_CONTRACT_ID,
    BOUNDED_MEAN_SCHEMA,
    BOUNDED_MEAN_SIGN_METHOD_ID,
    BOUNDED_MEAN_ZERO_P_METHOD_ID,
    MAX_BOUNDED_MEAN_SEEDS,
    MAX_BOUNDED_MEAN_UNITS,
    BoundedMeanDecision,
    BoundedMeanDecisionReason,
    BoundedMeanInferenceError,
    BoundedMeanInferencePlan,
    BoundedMeanInferenceResult,
    ConditionalSignResult,
    ConditionalSignStatus,
    PairedRowCorrectnessCounts,
    analyze_fixed_complete_bounded_mean,
)
from scientist_one.errors import ValidationError


def _unit_log_bounds(value: Fraction, terms: int = 150) -> tuple[Fraction, Fraction]:
    """For 1<=x<=2, ln(x)=2 sum z^(2j+1)/(2j+1), 0<=z<=1/3."""
    assert 1 <= value <= 2
    z = (value - 1) / (value + 1)
    square = z * z
    power, total = z, Fraction(0)
    for index in range(terms):
        total += power / (2 * index + 1)
        power *= square
    lower = 2 * total
    remainder_upper = 2 * power / ((2 * terms + 1) * (1 - square))
    return lower, lower + remainder_upper


_LOG_TWO_BOUNDS = _unit_log_bounds(Fraction(2))


def _log_bounds(value: Fraction) -> tuple[Fraction, Fraction]:
    assert value >= 2
    exponent = value.numerator.bit_length() - value.denominator.bit_length()
    if value < 1 << exponent:
        exponent -= 1
    mantissa = value / (1 << exponent)
    low, high = _unit_log_bounds(mantissa)
    return low + exponent * _LOG_TWO_BOUNDS[0], high + exponent * _LOG_TWO_BOUNDS[1]


def _sqrt_bounds(low: Fraction, high: Fraction) -> tuple[Fraction, Fraction]:
    scale = 10**120
    low_integer = math.isqrt(low.numerator * scale * scale // low.denominator)
    high_integer = math.isqrt(high.numerator * scale * scale // high.denominator)
    return Fraction(low_integer, scale), Fraction(high_integer + 1, scale)


def _negative_exp_bounds(exponent_magnitude: Fraction) -> tuple[Fraction, Fraction]:
    """Enclose exp(-q), 0<=q<=2048, without any transcendental library call."""
    assert 0 <= exponent_magnitude <= 2048
    argument = -exponent_magnitude / 4096
    term = total = Fraction(1)
    for index in range(1, 121):
        term = term * argument / index
        total += term
    # Alternating decreasing terms: even partial sum upper, next odd lower.
    upper = total
    lower = total + term * argument / 121
    down = Context(prec=200, rounding=ROUND_FLOOR, Emin=-999999, Emax=999999)
    up = Context(prec=200, rounding=ROUND_CEILING, Emin=-999999, Emax=999999)
    low = down.divide(Decimal(lower.numerator), Decimal(lower.denominator))
    high = up.divide(Decimal(upper.numerator), Decimal(upper.denominator))
    for _ in range(12):
        low = down.multiply(low, low)
        high = up.multiply(high, high)
    return Fraction(low), Fraction(high)


def _case(
    differences: tuple[int, ...],
    *,
    seed_count: int = 1,
    alpha: float = 0.05,
    benefit_margin: float = 0.02,
    harm_margin: float = 0.02,
    minimum_unit_count: int = 1,
) -> tuple[BoundedMeanInferencePlan, tuple[PairedRowCorrectnessCounts, ...]]:
    ids = tuple(f"row-{index}" for index in range(len(differences)))
    plan = BoundedMeanInferencePlan(
        alpha=alpha,
        benefit_margin=benefit_margin,
        harm_margin=harm_margin,
        minimum_unit_count=minimum_unit_count,
        unit_ids=ids,
        seed_order=tuple(range(seed_count)),
    )
    rows = tuple(
        PairedRowCorrectnessCounts(unit, seed_count, max(value, 0), max(-value, 0))
        for unit, value in zip(ids, differences, strict=True)
    )
    return plan, rows


def _analyze(
    differences: tuple[int, ...], **kwargs: object
) -> BoundedMeanInferenceResult:
    plan, rows = _case(differences, **kwargs)
    return analyze_fixed_complete_bounded_mean(plan=plan, rows=rows)


class BoundedMeanInferenceTests(unittest.TestCase):
    def test_exact_finite_two_point_population_coverage_and_decisions(self) -> None:
        # Independent finite-distribution checks, not a proof over every
        # population and not scientific execution or assumption authority.
        for count in (50, 100):
            results = tuple(
                _analyze(
                    (1,) * k + (-1,) * (count - k), benefit_margin=0.4, harm_margin=0.4
                )
                for k in range(count + 1)
            )
            alpha = Fraction.from_float(results[0].plan.alpha)
            margin = Fraction.from_float(0.4)
            for probability in (Fraction(1, 20), Fraction(1, 2), Fraction(19, 20)):
                with self.subTest(count=count, probability=probability):
                    mean = 2 * probability - 1
                    missed = falsely_certified = Fraction(0)
                    for k, result in enumerate(results):
                        mass = (
                            math.comb(count, k)
                            * probability**k
                            * (1 - probability) ** (count - k)
                        )
                        low = Fraction.from_float(result.confidence_low)
                        high = Fraction.from_float(result.confidence_high)
                        missed += mass * int(not low <= mean <= high)
                        true_assertions = {
                            BoundedMeanDecision.SUPPORTED: mean >= margin,
                            BoundedMeanDecision.FALSIFIED: mean <= -margin,
                            BoundedMeanDecision.EQUIVALENT_WITHIN_MARGINS: -margin
                            < mean
                            < margin,
                            BoundedMeanDecision.PARTIALLY_SUPPORTED: mean > 0,
                            BoundedMeanDecision.NEGATIVE: mean < 0,
                            BoundedMeanDecision.INCONCLUSIVE: True,
                        }
                        falsely_certified += mass * int(
                            not true_assertions[result.decision]
                        )
                    self.assertLessEqual(falsely_certified, missed)
                    self.assertLessEqual(missed, alpha)

    def test_mean_zero_p_bound_has_conservative_finite_null_rejection_rates(
        self,
    ) -> None:
        for count in (50, 100):
            results = tuple(
                _analyze((1,) * k + (-1,) * (count - k)) for k in range(count + 1)
            )
            # Symmetric independent +/-1 effects have exactly zero mean.
            for cutoff in (0.01, 0.05, 0.5):
                with self.subTest(count=count, cutoff=cutoff):
                    threshold = Fraction.from_float(cutoff)
                    rejection_probability = sum(
                        (
                            Fraction(math.comb(count, k), 2**count)
                            for k, result in enumerate(results)
                            if Fraction.from_float(result.mean_zero_p_upper)
                            <= threshold
                        ),
                        Fraction(0),
                    )
                    self.assertLessEqual(rejection_probability, threshold)

    def assert_oracle_enclosures(self, result: BoundedMeanInferenceResult) -> None:
        alpha = Fraction.from_float(result.plan.alpha)
        count, seeds = len(result.rows), len(result.plan.seed_order)
        mean = Fraction(result.mean_numerator, result.mean_denominator)
        log_low, log_high = _log_bounds(2 / alpha)
        radius_low, radius_high = _sqrt_bounds(
            2 * log_low / count, 2 * log_high / count
        )
        self.assertGreaterEqual(Fraction.from_float(result.radius_upper), radius_high)
        self.assertLessEqual(
            Fraction.from_float(result.confidence_low), max(-1, mean - radius_high)
        )
        self.assertGreaterEqual(
            Fraction.from_float(result.confidence_high), min(1, mean + radius_high)
        )
        self.assertLessEqual(
            Fraction.from_float(result.confidence_level_lower), 1 - alpha
        )
        self.assertGreaterEqual(result.confidence_low, -1)
        self.assertLessEqual(result.confidence_high, 1)
        self.assertLessEqual(result.confidence_low, result.mean_estimate)
        self.assertLessEqual(result.mean_estimate, result.confidence_high)
        self.assertEqual(result.mean_estimate, float(mean))
        # Bound excess should be at binary64 scale, not a hidden large pad.
        self.assertLess(
            float(Fraction.from_float(result.radius_upper) - radius_low),
            4 * math.ulp(result.radius_upper),
        )
        magnitude = Fraction(result.mean_numerator**2, 2 * count * seeds**2)
        _, exp_high = _negative_exp_bounds(magnitude)
        self.assertGreaterEqual(
            Fraction.from_float(result.mean_zero_p_upper), min(1, 2 * exp_high)
        )
        log_p_high = min(Fraction(0), _LOG_TWO_BOUNDS[1] - magnitude)
        self.assertGreaterEqual(
            Fraction.from_float(result.mean_zero_log_p_upper), log_p_high
        )
        self.assertGreater(result.mean_zero_p_upper, 0)
        self.assertLessEqual(result.mean_zero_p_upper, 1)

    def test_exact_integer_counts_and_grid_are_preserved(self) -> None:
        result = _analyze((-1,) * 80 + (16,) * 20, seed_count=16)
        self.assertEqual(result.row_effect_numerators, (-1,) * 80 + (16,) * 20)
        self.assertEqual(result.row_effect_denominator, 16)
        self.assertEqual((result.mean_numerator, result.mean_denominator), (240, 1600))
        self.assertEqual(result.mean_estimate, 0.15)
        self.assertEqual(len(result.rows), 100)
        self.assert_oracle_enclosures(result)

    def test_small_sample_all_ties_do_not_establish_equivalence(self) -> None:
        result = _analyze((0,) * 20)
        self.assertEqual(result.decision, BoundedMeanDecision.INCONCLUSIVE)
        self.assertAlmostEqual(result.confidence_low, -0.6073614619083, places=12)
        self.assertAlmostEqual(result.confidence_high, 0.6073614619083, places=12)
        self.assertEqual(result.mean_zero_p_upper, 1)
        self.assertEqual(
            result.auxiliary_sign.status, ConditionalSignStatus.ALL_TIES_NOT_TESTABLE
        )
        self.assertEqual(result.auxiliary_sign.non_tied_count, 0)
        self.assertEqual(result.auxiliary_sign.tie_count, 20)
        self.assertEqual(result.auxiliary_sign.p_value_upper, 1)
        self.assertGreater(
            0.95**20, 0.35
        )  # Counterexample probability, not test evidence.
        self.assert_oracle_enclosures(result)

    def test_sign_p_does_not_drive_mean_decision(self) -> None:
        small = _analyze((-1,) * 80 + (16,) * 20, seed_count=16)
        self.assertLess(small.auxiliary_sign.p_value_upper, 2e-9)
        self.assertGreater(small.mean_zero_p_upper, 0.6)
        self.assertEqual(small.decision, BoundedMeanDecision.INCONCLUSIVE)
        large = _analyze((-1,) * 800 + (16,) * 200, seed_count=16)
        self.assertEqual(
            (large.auxiliary_sign.negative_count, large.auxiliary_sign.positive_count),
            (800, 200),
        )
        self.assertEqual(large.decision, BoundedMeanDecision.SUPPORTED)
        self.assertLess(large.mean_zero_p_upper, 0.000027)
        self.assert_oracle_enclosures(large)

    def test_flipped_effects_reverse_mean_direction_not_sign_p(self) -> None:
        positive = _analyze((-1,) * 800 + (16,) * 200, seed_count=16)
        negative = _analyze((1,) * 800 + (-16,) * 200, seed_count=16)
        self.assertEqual(negative.decision, BoundedMeanDecision.FALSIFIED)
        self.assertEqual(positive.confidence_low, -negative.confidence_high)
        self.assertEqual(positive.confidence_high, -negative.confidence_low)
        self.assertEqual(positive.mean_zero_p_upper, negative.mean_zero_p_upper)
        self.assertEqual(
            positive.auxiliary_sign.p_value_upper, negative.auxiliary_sign.p_value_upper
        )
        self.assert_oracle_enclosures(negative)

    def test_seed_replication_does_not_increase_independent_n(self) -> None:
        one = _analyze((1,) * 80 + (-1,) * 20)
        many = _analyze((24,) * 80 + (-24,) * 20, seed_count=24)
        for name in (
            "mean_estimate",
            "radius_upper",
            "confidence_low",
            "confidence_high",
            "mean_zero_p_upper",
            "decision",
        ):
            self.assertEqual(getattr(one, name), getattr(many, name))
        self.assertEqual(len(many.rows), 100)

    def test_known_support_is_used_when_observed_range_is_degenerate(self) -> None:
        for effect in (-1, 0, 1):
            with self.subTest(effect=effect):
                result = _analyze((effect,))
                self.assertEqual(
                    (result.confidence_low, result.confidence_high), (-1, 1)
                )
                self.assertEqual(result.decision, BoundedMeanDecision.INCONCLUSIVE)
                self.assert_oracle_enclosures(result)

    def test_current_cap_has_explicit_power_limit_for_two_percent_margin(self) -> None:
        result = _analyze((0,) * 4096)
        self.assertGreater(result.radius_upper, 0.042)
        self.assertEqual(result.decision, BoundedMeanDecision.INCONCLUSIVE)
        wider = _analyze((0,) * 4096, benefit_margin=0.1, harm_margin=0.1)
        self.assertEqual(wider.decision, BoundedMeanDecision.EQUIVALENT_WITHIN_MARGINS)
        self.assert_oracle_enclosures(result)

    def test_equivalence_can_coexist_with_a_small_directional_mean(self) -> None:
        result = _analyze(
            (1,) * 4096, seed_count=20, benefit_margin=0.1, harm_margin=0.1
        )
        self.assertGreater(result.confidence_low, 0)
        self.assertEqual(result.decision, BoundedMeanDecision.EQUIVALENT_WITHIN_MARGINS)
        self.assertEqual(
            result.decision_reason, BoundedMeanDecisionReason.STRICT_MARGIN_EQUIVALENCE
        )
        self.assertNotEqual(result.mean_estimate, 0)

    def test_ordered_decision_boundaries_use_outward_endpoints_without_epsilon(
        self,
    ) -> None:
        plan, rows = _case(
            (1,) * 4096, seed_count=10, benefit_margin=0.5, harm_margin=0.5
        )
        result = analyze_fixed_complete_bounded_mean(plan=plan, rows=rows)
        low, high = result.confidence_low, result.confidence_high
        cases = (
            (low, BoundedMeanDecision.SUPPORTED),
            (math.nextafter(low, math.inf), BoundedMeanDecision.PARTIALLY_SUPPORTED),
            (high, BoundedMeanDecision.PARTIALLY_SUPPORTED),
            (
                math.nextafter(high, math.inf),
                BoundedMeanDecision.EQUIVALENT_WITHIN_MARGINS,
            ),
        )
        for margin, expected in cases:
            with self.subTest(margin=margin):
                value = analyze_fixed_complete_bounded_mean(
                    plan=replace(plan, benefit_margin=margin), rows=rows
                )
                self.assertEqual(value.decision, expected)
        negative_plan, negative_rows = _case(
            (-1,) * 4096, seed_count=10, benefit_margin=0.5, harm_margin=0.5
        )
        negative_cases = (
            (low, BoundedMeanDecision.FALSIFIED),
            (math.nextafter(low, math.inf), BoundedMeanDecision.NEGATIVE),
            (high, BoundedMeanDecision.NEGATIVE),
            (
                math.nextafter(high, math.inf),
                BoundedMeanDecision.EQUIVALENT_WITHIN_MARGINS,
            ),
        )
        for margin, expected in negative_cases:
            with self.subTest(harm_margin=margin):
                value = analyze_fixed_complete_bounded_mean(
                    plan=replace(negative_plan, harm_margin=margin), rows=negative_rows
                )
                self.assertEqual(value.decision, expected)

    def test_fixed_minimum_size_failure_is_retained_not_an_exclusion(self) -> None:
        result = _analyze((1,) * 100, minimum_unit_count=101)
        self.assertGreater(result.confidence_low, 0.7)
        self.assertEqual(result.decision, BoundedMeanDecision.INCONCLUSIVE)
        self.assertEqual(
            result.decision_reason, BoundedMeanDecisionReason.MINIMUM_SIZE_NOT_MET
        )
        self.assertEqual(len(result.rows), 100)

    def test_mean_and_sign_underflow_are_positive_upper_bounds(self) -> None:
        for effect in (-24, 24):
            with self.subTest(effect=effect):
                result = _analyze((effect,) * 4096, seed_count=24)
                self.assertEqual(result.mean_zero_p_upper, math.ulp(0.0))
                self.assertTrue(result.mean_zero_p_binary64_underflow_limited)
                self.assertTrue(math.isfinite(result.mean_zero_log_p_upper))
                self.assertLess(result.mean_zero_log_p_upper, -2047)
                self.assertEqual(result.auxiliary_sign.p_value_upper, math.ulp(0.0))
                self.assertTrue(result.auxiliary_sign.binary64_underflow_limited)
                self.assertEqual(
                    (
                        result.auxiliary_sign.p_numerator,
                        result.auxiliary_sign.p_denominator,
                    ),
                    (1, 2**4095),
                )
                self.assert_oracle_enclosures(result)

    def test_oracle_checks_adversarial_alpha_and_fractional_mean_vectors(self) -> None:
        cases = (
            ((1,), 24, math.ulp(0.0)),
            ((1, -1), 1, math.nextafter(1.0, 0.0)),
            ((1,) * 37 + (-3,) * 11, 7, 0.01),
            ((1,) * 64 + (0,) * 64, 3, math.nextafter(0.05, 0.0)),
            ((-1,) * 64 + (0,) * 64, 3, math.nextafter(0.05, 1.0)),
            ((1,) * 1000, 1, 1e-300),
            ((1,) * 1500, 1, 0.5),
            ((1,) * 1490, 1, 0.9),
        )
        for effects, seeds, alpha in cases:
            with self.subTest(count=len(effects), seeds=seeds, alpha=alpha):
                self.assert_oracle_enclosures(
                    _analyze(effects, seed_count=seeds, alpha=alpha)
                )

    def test_subnormal_alpha_does_not_round_claimed_confidence_to_one(self) -> None:
        result = _analyze((0,), alpha=math.ulp(0.0))
        self.assertLess(result.confidence_level_lower, 1)
        self.assertEqual(result.confidence_level_lower, math.nextafter(1.0, 0.0))
        self.assertEqual(result.plan.alpha, math.ulp(0.0))

    def test_results_do_not_depend_on_ambient_decimal_context(self) -> None:
        plan, rows = _case((-1,) * 80 + (16,) * 20, seed_count=16)
        expected = analyze_fixed_complete_bounded_mean(plan=plan, rows=rows)
        with localcontext() as context:
            context.prec = 2
            context.rounding = ROUND_DOWN
            context.Emax = 2
            context.Emin = -2
            context.traps[Inexact] = True
            actual = analyze_fixed_complete_bounded_mean(plan=plan, rows=rows)
        self.assertEqual(actual, expected)

    def test_conditional_sign_exact_oracle_all_small_count_combinations(self) -> None:
        for positive in range(13):
            for negative in range(13):
                count = positive + negative
                result = ConditionalSignResult(positive, negative, 2)
                expected = min(
                    Fraction(1),
                    Fraction(
                        2
                        * sum(
                            math.comb(count, index)
                            for index in range(min(positive, negative) + 1)
                        ),
                        2**count,
                    ),
                )
                self.assertEqual(
                    Fraction(result.p_numerator, result.p_denominator), expected
                )
                self.assertGreaterEqual(
                    Fraction.from_float(result.p_value_upper), expected
                )
                self.assertEqual(result.non_tied_count, count)
                if count:
                    self.assertEqual(result.status, ConditionalSignStatus.TESTABLE)

    def test_sign_subnormal_boundary_is_exact_not_a_zero_p_value(self) -> None:
        for count in (1074, 1075, 1076):
            with self.subTest(non_tied_count=count):
                result = ConditionalSignResult(count, 0, 0)
                expected = Fraction(1, 2 ** (count - 1))
                self.assertEqual(
                    Fraction(result.p_numerator, result.p_denominator), expected
                )
                self.assertGreaterEqual(
                    Fraction.from_float(result.p_value_upper), expected
                )
                self.assertEqual(result.binary64_underflow_limited, count > 1075)
                self.assertGreater(result.p_value_upper, 0)

    def test_nonfinite_boolean_and_non_binary64_scalar_inputs_are_rejected(
        self,
    ) -> None:
        plan, _ = _case((0,))
        for name in (
            "alpha",
            "benefit_margin",
            "harm_margin",
            "support_low",
            "support_high",
        ):
            for value in (
                True,
                False,
                float("inf"),
                float("-inf"),
                float("nan"),
                ".05",
                Decimal(".05"),
                Fraction(1, 20),
                10**1000,
                None,
            ):
                with self.subTest(name=name, value_type=type(value).__name__):
                    with self.assertRaises(BoundedMeanInferenceError):
                        replace(plan, **{name: value})
        self.assertIsInstance(BoundedMeanInferenceError("invalid"), ValidationError)

    def test_scalar_domains_and_known_support_are_closed(self) -> None:
        plan, _ = _case((0,))
        cases = (
            {"alpha": 0},
            {"alpha": 1},
            {"alpha": -0.05},
            {"alpha": 2},
            {"benefit_margin": 0},
            {"benefit_margin": -1},
            {"benefit_margin": 1.01},
            {"harm_margin": 0},
            {"harm_margin": -1},
            {"harm_margin": 1.01},
            {"support_low": 0, "support_high": 0},
            {"support_low": -2},
            {"support_high": 2},
            {"support_low": math.nextafter(-1.0, 0.0)},
            {"support_high": math.nextafter(1.0, 0.0)},
            {"minimum_unit_count": True},
            {"minimum_unit_count": 1.0},
            {"minimum_unit_count": 0},
            {"minimum_unit_count": 4097},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(BoundedMeanInferenceError):
                    replace(plan, **changes)
        accepted = replace(
            plan, benefit_margin=1, harm_margin=1, support_low=-1, support_high=1
        )
        self.assertIs(type(accepted.benefit_margin), float)

    def test_unit_and_seed_grid_bounds_and_identities_are_strict(self) -> None:
        self.assertEqual((MAX_BOUNDED_MEAN_UNITS, MAX_BOUNDED_MEAN_SEEDS), (4096, 24))
        plan, _ = _case((0, 0))
        cases = (
            {"unit_ids": ()},
            {"unit_ids": ["row-0", "row-1"]},
            {"unit_ids": ("row-0", "row-0")},
            {"unit_ids": ("",)},
            {"unit_ids": (True,)},
            {"unit_ids": ("../unit",)},
            {"unit_ids": tuple(f"row-{i}" for i in range(4097))},
            {"unit_ids": tuple(f"row-{i}" for i in range(18445))},
            {"seed_order": ()},
            {"seed_order": [0]},
            {"seed_order": (0, 0)},
            {"seed_order": (True,)},
            {"seed_order": (1.0,)},
            {"seed_order": (-1,)},
            {"seed_order": tuple(range(25))},
        )
        for changes in cases:
            with self.subTest(field=tuple(changes)):
                with self.assertRaises(BoundedMeanInferenceError):
                    replace(plan, **changes)

    def test_counts_reject_boolean_noninteger_and_support_violations(self) -> None:
        row = PairedRowCorrectnessCounts("row-0", 4, 2, 3)
        for name in (
            "seed_count",
            "candidate_correct_count",
            "reference_correct_count",
        ):
            for value in (True, False, 1.0, float("nan"), "1", -1, 25, None):
                with self.subTest(name=name, value=value):
                    with self.assertRaises(BoundedMeanInferenceError):
                        replace(row, **{name: value})
        for changes in (
            {"seed_count": 0},
            {"candidate_correct_count": 5},
            {"reference_correct_count": 5},
        ):
            with self.assertRaises(BoundedMeanInferenceError):
                replace(row, **changes)

    def test_excluded_added_reordered_and_incomplete_rows_are_rejected(self) -> None:
        plan, rows = _case((1, 0, -1), seed_count=2)
        cases = (
            (),
            rows[:-1],
            rows[1:],
            rows[::-1],
            rows + (rows[0],),
            (rows[0], rows[0], rows[2]),
            (replace(rows[0], unit_id="replacement"),) + rows[1:],
            (replace(rows[0], seed_count=1),) + rows[1:],
            (rows[0].to_dict(),) + rows[1:],
            list(rows),
            (rows[0],) * 4097,
        )
        for wrong in cases:
            with self.subTest(count=len(wrong)):
                with self.assertRaises(BoundedMeanInferenceError):
                    analyze_fixed_complete_bounded_mean(plan=plan, rows=wrong)
        with self.assertRaises(BoundedMeanInferenceError):
            analyze_fixed_complete_bounded_mean(plan=plan.to_dict(), rows=rows)
        with self.assertRaises(TypeError):
            analyze_fixed_complete_bounded_mean(
                plan=plan, rows=rows, excluded_unit_ids=("row-1",)
            )

    def test_sign_counts_reject_invalid_totals_and_values(self) -> None:
        for values in (
            (0, 0, 0),
            (4096, 1, 0),
            (0, 0, 4097),
            (True, 0, 1),
            (1, -1, 2),
            (1, 1.0, 0),
        ):
            with self.subTest(values=values):
                with self.assertRaises(BoundedMeanInferenceError):
                    ConditionalSignResult(*values)

    def test_dtos_are_immutable_rederived_and_have_no_issuing_surface(self) -> None:
        result = _analyze((1, 0, -1))
        for value, name, replacement in (
            (result, "mean_estimate", 1.0),
            (result.plan, "alpha", 0.1),
            (result.rows[0], "candidate_correct_count", 0),
            (result.auxiliary_sign, "p_value_upper", 0),
        ):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, name, replacement)
        # Python 3.14 changed dataclasses.replace's init=False failure type.
        with self.assertRaises((TypeError, ValueError)):
            replace(result, mean_zero_p_upper=0)
        with self.assertRaises(TypeError):
            BoundedMeanInferenceResult(result.plan, result.rows, mean_zero_p_upper=0)
        self.assertEqual(replace(result), result)
        init_fields = {item.name for item in fields(result) if item.init}
        self.assertEqual(init_fields, {"plan", "rows"})
        payload = result.to_dict()
        payload["plan"]["unit_ids"].clear()
        payload["rows"].clear()
        payload["auxiliary_sign"]["p_value_upper"] = 0
        self.assertEqual(len(result.rows), 3)
        self.assertEqual(len(result.plan.unit_ids), 3)
        self.assertEqual(result.auxiliary_sign.p_value_upper, 1)

    def test_input_validation_is_replayed_without_trusting_a_dto_label(self) -> None:
        plan, rows = _case((0, 1))
        object.__setattr__(rows[0], "candidate_correct_count", 2)
        with self.assertRaises(BoundedMeanInferenceError):
            analyze_fixed_complete_bounded_mean(plan=plan, rows=rows)
        plan, rows = _case((0, 1))
        object.__setattr__(plan, "support_high", 0.5)
        with self.assertRaises(BoundedMeanInferenceError):
            analyze_fixed_complete_bounded_mean(plan=plan, rows=rows)

    def test_result_owns_numeric_copies_not_caller_dto_references(self) -> None:
        plan, rows = _case((0, 1))
        result = analyze_fixed_complete_bounded_mean(plan=plan, rows=rows)
        object.__setattr__(rows[0], "candidate_correct_count", 1)
        object.__setattr__(plan, "alpha", 0.1)
        self.assertEqual(result.rows[0].candidate_correct_count, 0)
        self.assertEqual(result.plan.alpha, 0.05)
        self.assertEqual(result.row_effect_numerators, (0, 1))

    def test_new_explicit_schema_and_scalar_meaning_do_not_relabel_bootstrap(
        self,
    ) -> None:
        result = _analyze((0, 1, -1), seed_count=24)
        value = result.to_dict()
        self.assertEqual(value["schema"], BOUNDED_MEAN_SCHEMA)
        self.assertEqual(value["profile_id"], BOUNDED_MEAN_PROFILE_ID)
        self.assertEqual(value["procedure_id"], BOUNDED_MEAN_PROCEDURE_ID)
        self.assertEqual(value["interval_method_id"], BOUNDED_MEAN_INTERVAL_METHOD_ID)
        self.assertEqual(value["mean_zero_p_method_id"], BOUNDED_MEAN_ZERO_P_METHOD_ID)
        self.assertEqual(value["decision_rule_id"], BOUNDED_MEAN_DECISION_RULE_ID)
        self.assertEqual(
            value["numerical_contract_id"], BOUNDED_MEAN_NUMERICAL_CONTRACT_ID
        )
        self.assertEqual(value["plan"]["schema"], BOUNDED_MEAN_PLAN_SCHEMA)
        self.assertEqual(
            value["plan"]["scalar_contract_id"], BOUNDED_MEAN_SCALAR_CONTRACT_ID
        )
        self.assertEqual(
            value["auxiliary_sign"]["method_id"], BOUNDED_MEAN_SIGN_METHOD_ID
        )
        self.assertEqual(
            value["materialization_scope"], "PURE_NON_AUTHORITATIVE_NUMERIC"
        )
        self.assertEqual(value["mean_zero_null"], "E[D]=0")
        self.assertEqual(value["auxiliary_sign"]["null"], "P(D>0 | D!=0)=1/2")
        self.assertNotEqual(Fraction.from_float(result.plan.alpha), Fraction(1, 20))
        serialized = json.dumps(value, allow_nan=False, sort_keys=True)
        self.assertNotIn("bootstrap", serialized)
        self.assertNotIn("approval", serialized)
        self.assertNotIn("signature", serialized)
        self.assertNotIn("artifact", serialized)
        self.assertEqual(json.loads(serialized), value)


if __name__ == "__main__":
    unittest.main()
